//! Cases of calendars, bindings, collection properties and grants.

use davhaven_domain::{
    BindingFact, CalendarKind, CalendarSlug, CollectionKey, CollectionKind, ComponentKind, GrantAccess, GrantFact,
    GrantSource, GrantStatus, PrincipalKind, TenantSettings, Transparency, Uid,
};
use davhaven_ports::{CalendarFilter, ChangeKind, CollectionProperty, PageReq, PropertyScope, UniqueKey};

use super::Outcome;
use super::world::{Db, StoreChecks, begin, binding, calendar, epoch, grant, id, key, principal, seed};
use crate::suite::Checks;

/// Creating, reading, listing and updating calendars.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn calendars_crud(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let mut work = calendar(0x310, world.olivia, "work", CalendarKind::User)?;
    work.description = Some("Things to do".to_owned());
    work.color = Some("#112233".to_owned());
    work.sort_order = 3;
    work.components = vec![ComponentKind::Event];
    work.timezone_ics = Some("BEGIN:VTIMEZONE\r\nEND:VTIMEZONE\r\n".to_owned());
    let created = tx.calendars().create(work.clone()).await?;
    checks.equal(
        &created.tenant_id,
        &world.a,
        "the store binds the calendar to the transaction's tenant",
    );
    checks.equal(
        &created.sync_seq,
        &0,
        "a new calendar starts at sequence 0 whatever the entity said",
    );
    checks.equal(&created.sync_min_seq, &0, "with minimum sequence 0");
    checks.equal(
        &created.sync_epoch,
        &work.sync_epoch,
        "and keeps the epoch of the entity",
    );
    checks.equal(&created.version, &1, "a new calendar has version 1");
    checks.equal(
        &created.created_at,
        &created.updated_at,
        "creation stamps both times alike",
    );
    checks.that(
        created.created_at != epoch() && created.deleted_at.is_none(),
        "stamped and live",
    );
    checks.equal(&created.description, &work.description, "the description is stored");
    checks.equal(&created.color, &work.color, "the color is stored");
    checks.equal(&created.sort_order, &3, "the sort order is stored");
    checks.equal(
        &created.components,
        &vec![ComponentKind::Event],
        "the component set is stored",
    );
    checks.equal(&created.timezone_ics, &work.timezone_ics, "the time zone is stored");
    checks.equal(
        &tx.calendars().get(created.id).await?,
        &created,
        "get returns what create returned",
    );
    checks.equal(
        &tx.calendars().get_by_slug(world.olivia, &created.slug).await?,
        &created,
        "get by owner and slug",
    );
    checks.not_found(tx.calendars().get(id(0x999)).await, "an unknown calendar");
    checks.not_found(
        tx.calendars().get_by_slug(world.mia, &created.slug).await,
        "the slug of another owner",
    );
    checks.not_found(
        tx.calendars()
            .create(calendar(0x311, id(0x999), "orphan", CalendarKind::User)?)
            .await,
        "a calendar of an unknown owner",
    );

    let owned: Vec<_> = tx
        .calendars()
        .list_owned(world.olivia)
        .await?
        .iter()
        .map(|found| found.id)
        .collect();
    checks.equal(
        &owned,
        &vec![world.personal, world.shared, created.id],
        "list_owned is in id order",
    );
    let many = tx
        .calendars()
        .get_many(&[created.id, id(0x999), world.personal, created.id])
        .await?;
    checks.equal(
        &many.iter().map(|found| found.id).collect::<Vec<_>>(),
        &vec![world.personal, created.id],
        "get_many skips unknown ids and answers in id order",
    );
    let by_owner = tx
        .calendars()
        .list(
            &CalendarFilter {
                owner: Some(world.olivia),
                ..CalendarFilter::default()
            },
            PageReq::default(),
        )
        .await?;
    checks.equal(&by_owner.items.len(), &3, "the owner filter");
    let by_kind = tx
        .calendars()
        .list(
            &CalendarFilter {
                kind: Some(CalendarKind::Group),
                ..CalendarFilter::default()
            },
            PageReq::default(),
        )
        .await?;
    checks.equal(
        &by_kind.items.iter().map(|found| found.id).collect::<Vec<_>>(),
        &vec![world.team_calendar],
        "the kind filter",
    );
    let by_slug = tx
        .calendars()
        .list(
            &CalendarFilter {
                slug: Some(key(CalendarSlug::parse("work"))?),
                ..CalendarFilter::default()
            },
            PageReq::default(),
        )
        .await?;
    checks.equal(&by_slug.items.len(), &1, "the slug filter");
    let by_text = tx
        .calendars()
        .list(
            &CalendarFilter {
                text: Some("CALENDAR WO".to_owned()),
                ..CalendarFilter::default()
            },
            PageReq::default(),
        )
        .await?;
    checks.equal(
        &by_text.items.len(),
        &1,
        "the text filter is a case-insensitive substring of the display name",
    );
    let first = tx
        .calendars()
        .list(&CalendarFilter::default(), PageReq::first(2))
        .await?;
    checks.equal(&first.items.len(), &2, "a page of two");
    if let Some(cursor) = first.next {
        let rest = tx
            .calendars()
            .list(&CalendarFilter::default(), PageReq::first(2).after(cursor))
            .await?;
        checks.equal(&rest.items.len(), &2, "the rest");
        checks.equal(&rest.next, &None, "is the last page");
    } else {
        checks.fail("a page of two out of four calendars names a cursor");
    }

    let mut changed = calendar(0x310, world.mia, "other-slug", CalendarKind::Managed)?;
    changed.display_name = "Changed".into();
    changed.description = None;
    changed.color = Some("#FFFFFF".to_owned());
    changed.sort_order = 9;
    changed.components = vec![ComponentKind::Todo, ComponentKind::Journal];
    changed.timezone_ics = None;
    let updated = tx.calendars().update(changed.clone(), created.version).await?;
    checks.equal(&updated.version, &2, "an update bumps the version");
    checks.equal(&updated.sync_seq, &1, "and advances the sync sequence");
    checks.equal(&updated.slug, &created.slug, "the slug is immutable");
    checks.equal(&updated.kind, &created.kind, "the kind is immutable");
    checks.equal(&updated.owner_id, &created.owner_id, "the owner is immutable");
    checks.equal(
        &updated.sync_epoch,
        &created.sync_epoch,
        "the epoch is not changed by an update",
    );
    checks.equal(&updated.display_name.as_str(), &"Changed", "the display name changes");
    checks.equal(&updated.description, &None, "the description changes");
    checks.equal(&updated.sort_order, &9, "the sort order changes");
    checks.equal(
        &updated.components,
        &vec![ComponentKind::Todo, ComponentKind::Journal],
        "the components change",
    );
    checks.equal(&updated.timezone_ics, &None, "the time zone changes");
    checks.equal(&updated.created_at, &created.created_at, "creation time stays");
    checks.precondition_failed(
        tx.calendars().update(changed.clone(), created.version).await,
        "a stale version",
    );
    checks.not_found(
        tx.calendars()
            .update(calendar(0x998, world.olivia, "ghost", CalendarKind::User)?, 1)
            .await,
        "an unknown calendar",
    );
    tx.commit().await?;
    Ok(())
}

/// Soft deletion hides a calendar everywhere, frees its slug and leaves it to the purge.
pub(super) async fn calendars_soft_delete_lock_touch_purge(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let personal = tx.calendars().get(world.personal).await?;
    checks.precondition_failed(tx.calendars().soft_delete(world.shared, 99).await, "a stale version");
    tx.calendars().soft_delete(world.personal, personal.version).await?;
    checks.not_found(tx.calendars().get(world.personal).await, "get of a deleted calendar");
    checks.not_found(
        tx.calendars().get_by_slug(world.olivia, &personal.slug).await,
        "get by slug of a deleted calendar",
    );
    checks.equal(
        &tx.calendars()
            .list_owned(world.olivia)
            .await?
            .iter()
            .map(|found| found.id)
            .collect::<Vec<_>>(),
        &vec![world.shared],
        "list_owned skips it",
    );
    checks.equal(
        &tx.calendars().get_many(&[world.personal, world.shared]).await?.len(),
        &1,
        "get_many skips it",
    );
    checks.equal(
        &tx.calendars()
            .list(&CalendarFilter::default(), PageReq::default())
            .await?
            .items
            .len(),
        &2,
        "list skips it",
    );
    checks.not_found(
        tx.calendars().lock(&[world.personal]).await,
        "locking a deleted calendar",
    );
    checks.not_found(
        tx.calendars().touch(world.personal).await,
        "touching a deleted calendar",
    );
    checks.not_found(
        tx.calendars().soft_delete(world.personal, personal.version + 1).await,
        "deleting it again",
    );
    checks.not_found(
        tx.calendars().update(personal.clone(), personal.version + 1).await,
        "updating it",
    );
    checks.not_found(
        tx.calendars().access_facts(world.personal, None).await,
        "authorization facts of it",
    );
    let again = tx
        .calendars()
        .create(calendar(0x320, world.olivia, "personal", CalendarKind::Personal)?)
        .await?;
    checks.equal(
        &again.slug,
        &personal.slug,
        "the slug of a deleted calendar is free again",
    );

    let locked = tx
        .calendars()
        .lock(&[world.team_calendar, world.shared, world.shared])
        .await?;
    checks.equal(
        &locked.iter().map(|found| found.id).collect::<Vec<_>>(),
        &vec![world.shared, world.team_calendar],
        "lock answers in ascending id order and counts duplicates once",
    );
    checks.not_found(
        tx.calendars().lock(&[world.shared, id(0x999)]).await,
        "locking an unknown calendar",
    );

    let shared = tx.calendars().get(world.shared).await?;
    checks.equal(&tx.calendars().touch(world.shared).await?, &1, "the first touch");
    checks.equal(&tx.calendars().touch(world.shared).await?, &2, "the second touch");
    let touched = tx.calendars().get(world.shared).await?;
    checks.equal(&touched.sync_seq, &2, "touch advances the sequence");
    checks.equal(&touched.version, &shared.version, "and nothing else");
    checks.equal(&touched.updated_at, &shared.updated_at, "not even the update time");
    checks.not_found(tx.calendars().touch(id(0x999)).await, "touching an unknown calendar");

    checks.not_found(tx.calendars().purge(world.shared).await, "purging a live calendar");
    tx.calendars().purge(world.personal).await?;
    checks.not_found(tx.calendars().purge(world.personal).await, "purging twice");
    tx.commit().await?;
    Ok(())
}

/// Slugs are unique per owner among live calendars.
pub(super) async fn calendars_unique_slugs(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    checks.unique(
        tx.calendars()
            .create(calendar(0x330, world.olivia, "personal", CalendarKind::User)?)
            .await,
        UniqueKey::CalendarSlug,
        "a duplicate slug of the same owner",
    );
    let other = tx
        .calendars()
        .create(calendar(0x331, world.mia, "personal", CalendarKind::Personal)?)
        .await?;
    checks.equal(&other.owner_id, &world.mia, "another owner may use the slug");
    let doomed = tx.calendars().get(world.personal).await?;
    tx.calendars().soft_delete(doomed.id, doomed.version).await?;
    tx.calendars()
        .create(calendar(0x332, world.olivia, "personal", CalendarKind::Personal)?)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Which calendars a principal can see without a binding, and the one-query authorization facts.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn calendars_visibility_and_facts(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    for (n, name) in [(0x140, "rita"), (0x141, "paul"), (0x142, "dora"), (0x144, "gary")] {
        tx.principals().create(principal(n, name, PrincipalKind::User)?).await?;
    }
    tx.principals()
        .create(principal(0x143, "viewers", PrincipalKind::Group)?)
        .await?;
    let (rita, paul, dora, viewers, gary) = (id(0x140), id(0x141), id(0x142), id(0x143), id(0x144));
    tx.memberships().add_member(viewers, gary).await?;
    tx.grants()
        .create(grant(0x601, world.shared, rita, GrantStatus::Accepted))
        .await?;
    tx.grants()
        .create(grant(0x602, world.shared, paul, GrantStatus::Pending))
        .await?;
    tx.grants()
        .create(grant(0x603, world.shared, dora, GrantStatus::Declined))
        .await?;
    tx.grants()
        .create(grant(0x604, world.personal, viewers, GrantStatus::Accepted))
        .await?;

    let ids = |calendars: Vec<davhaven_domain::Calendar>| -> Vec<davhaven_domain::CalendarId> {
        calendars.iter().map(|found| found.id).collect()
    };
    checks.equal(
        &ids(tx.calendars().visible_without_binding(rita).await?),
        &vec![world.shared],
        "an accepted grant",
    );
    checks.equal(
        &ids(tx.calendars().visible_without_binding(paul).await?),
        &Vec::new(),
        "a pending grant gives nothing",
    );
    checks.equal(
        &ids(tx.calendars().visible_without_binding(dora).await?),
        &Vec::new(),
        "a declined grant gives nothing",
    );
    checks.equal(
        &ids(tx.calendars().visible_without_binding(gary).await?),
        &vec![world.personal],
        "an accepted grant to a group of the principal",
    );
    checks.equal(
        &ids(tx.calendars().visible_without_binding(world.mia).await?),
        &vec![world.team_calendar],
        "the calendars of a group the principal belongs to",
    );
    checks.equal(
        &ids(tx.calendars().visible_without_binding(world.olivia).await?),
        &Vec::new(),
        "calendars the principal owns are not listed",
    );
    let hidden = tx
        .bindings()
        .create({
            let mut hidden = binding(0x501, rita, world.shared, "projects")?;
            hidden.hidden = true;
            hidden
        })
        .await?;
    checks.equal(
        &ids(tx.calendars().visible_without_binding(rita).await?),
        &Vec::new(),
        "calendars with a binding are not listed, hidden bindings included",
    );

    let facts = tx.calendars().access_facts(world.shared, Some(rita)).await?;
    checks.equal(&facts.calendar_kind, &CalendarKind::User, "the kind of the calendar");
    checks.equal(&facts.owner, &world.olivia, "the owner");
    checks.equal(&facts.owner_kind, &PrincipalKind::User, "the kind of the owner");
    checks.equal(&facts.memberships, &Vec::new(), "no memberships");
    checks.equal(
        &facts.grants,
        &vec![
            GrantFact {
                grantee: rita,
                access: GrantAccess::ReadWrite,
                status: GrantStatus::Accepted,
                required: false,
            },
            GrantFact {
                grantee: paul,
                access: GrantAccess::ReadWrite,
                status: GrantStatus::Pending,
                required: false,
            },
            GrantFact {
                grantee: dora,
                access: GrantAccess::ReadWrite,
                status: GrantStatus::Declined,
                required: false,
            },
        ],
        "all grants of the calendar, pending and declined included, in id order",
    );
    checks.equal(
        &facts.binding,
        &Some(BindingFact {
            id: hidden.id,
            hidden: true,
        }),
        "the caller's binding",
    );
    checks.that(
        *facts.tenant_settings == TenantSettings::default(),
        "the settings of the tenant",
    );
    // A grant that is marked required says so in the facts, for the people it reaches through their group.
    let mut required = grant(0x605, world.team_calendar, viewers, GrantStatus::Accepted);
    required.required = true;
    tx.grants().create(required).await?;
    let required_facts = tx.calendars().access_facts(world.team_calendar, Some(gary)).await?;
    checks.equal(
        &required_facts.grants,
        &vec![GrantFact {
            grantee: viewers,
            access: GrantAccess::ReadWrite,
            status: GrantStatus::Accepted,
            required: true,
        }],
        "the facts carry the required flag of a grant",
    );
    let group_facts = tx
        .calendars()
        .access_facts(world.team_calendar, Some(world.mia))
        .await?;
    checks.equal(&group_facts.memberships, &vec![world.team], "the groups of the caller");
    checks.equal(&group_facts.owner_kind, &PrincipalKind::Group, "a group as owner");
    let anonymous = tx.calendars().access_facts(world.shared, None).await?;
    checks.that(
        anonymous.memberships.is_empty() && anonymous.binding.is_none(),
        "a caller without a principal has no memberships and no binding",
    );
    checks.not_found(
        tx.calendars().access_facts(id(0x999), None).await,
        "facts of an unknown calendar",
    );
    let many = tx
        .calendars()
        .access_facts_many(&[world.shared, id(0x999), world.personal, world.shared], Some(rita))
        .await?;
    checks.equal(
        &many.iter().map(|(calendar, _)| *calendar).collect::<Vec<_>>(),
        &vec![world.shared, world.personal, world.shared],
        "facts for several calendars come in the order asked, unknown ones skipped",
    );
    Ok(())
}

/// Bindings and their home change log.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn bindings(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let home = CollectionKey {
        kind: CollectionKind::Home,
        id: world.olivia.as_uuid(),
    };
    let epoch_of_home = tx.changes().state(home).await?.epoch;
    let first = tx
        .bindings()
        .create(binding(0x501, world.olivia, world.personal, "personal")?)
        .await?;
    checks.equal(&first.version, &1, "a new binding has version 1");
    checks.equal(&first.tenant_id, &world.a, "bound to the tenant of the transaction");
    checks.equal(&tx.bindings().get(first.id).await?, &first, "get");
    checks.equal(
        &tx.bindings().get_by_slug(world.olivia, &first.slug).await?,
        &first,
        "get by slug",
    );
    checks.equal(
        &tx.bindings().find_for_calendar(world.olivia, world.personal).await?,
        &Some(first.clone()),
        "find for a calendar",
    );
    checks.equal(
        &tx.bindings().find_for_calendar(world.olivia, world.shared).await?,
        &None,
        "no binding for another calendar",
    );
    let mut hidden = binding(0x502, world.olivia, world.shared, "projects")?;
    hidden.hidden = true;
    let second = tx.bindings().create(hidden).await?;
    let listed = tx.bindings().list_for(world.olivia).await?;
    checks.equal(
        &listed.iter().map(|bound| bound.binding.id).collect::<Vec<_>>(),
        &vec![first.id, second.id],
        "list_for is in binding id order and includes hidden bindings",
    );
    checks.equal(
        &listed.iter().map(|bound| bound.calendar.id).collect::<Vec<_>>(),
        &vec![world.personal, world.shared],
        "with their calendars",
    );
    checks.equal(
        &tx.bindings()
            .list_for_calendar(world.personal)
            .await?
            .iter()
            .map(|found| found.id)
            .collect::<Vec<_>>(),
        &vec![first.id],
        "the bindings of a calendar",
    );
    checks.not_found(
        tx.bindings().list_for_calendar(id(0x999)).await,
        "the bindings of an unknown calendar",
    );

    checks.unique(
        tx.bindings()
            .create(binding(0x503, world.olivia, world.team_calendar, "personal")?)
            .await,
        UniqueKey::BindingSlug,
        "a duplicate slug in the home",
    );
    checks.unique(
        tx.bindings()
            .create(binding(0x504, world.olivia, world.personal, "again")?)
            .await,
        UniqueKey::BindingCalendar,
        "a second binding of the same calendar",
    );
    checks.not_found(
        tx.bindings()
            .create(binding(0x505, world.olivia, id(0x999), "ghost")?)
            .await,
        "a binding of an unknown calendar",
    );
    checks.not_found(
        tx.bindings()
            .create(binding(0x506, id(0x999), world.team_calendar, "ghost")?)
            .await,
        "a binding of an unknown principal",
    );

    let mut changed = first.clone();
    changed.display_name = Some("Mine".to_owned());
    changed.color = Some("#00FF00".to_owned());
    changed.sort_order = Some(4);
    changed.schedule_transp = Some(Transparency::Transparent);
    changed.hidden = true;
    let updated = tx.bindings().update(changed.clone(), first.version).await?;
    checks.equal(&updated.version, &2, "an update bumps the version");
    checks.equal(
        &updated.display_name.as_deref(),
        &Some("Mine"),
        "the display name override",
    );
    checks.equal(&updated.sort_order, &Some(4), "the sort order override");
    checks.equal(
        &updated.schedule_transp,
        &Some(Transparency::Transparent),
        "the transparency override",
    );
    checks.that(updated.hidden, "hidden");
    checks.equal(&updated.slug, &first.slug, "the slug does not change");
    checks.precondition_failed(
        tx.bindings().update(changed.clone(), first.version).await,
        "a stale version",
    );
    checks.not_found(
        tx.bindings()
            .update(binding(0x998, world.olivia, world.personal, "x")?, 1)
            .await,
        "an unknown binding",
    );

    tx.properties()
        .set(CollectionProperty {
            calendar_id: world.personal,
            scope: PropertyScope::Binding(first.id),
            ns: "DAV:".to_owned(),
            name: "displayname".to_owned(),
            value_xml: "<D:displayname xmlns:D=\"DAV:\">Mine</D:displayname>".to_owned(),
        })
        .await?;
    tx.bindings().delete(first.id).await?;
    checks.not_found(tx.bindings().get(first.id).await, "a deleted binding");
    checks.not_found(tx.bindings().delete(first.id).await, "deleting twice");
    checks.not_found(
        tx.properties()
            .list(world.personal, PropertyScope::Binding(first.id))
            .await,
        "the properties of a deleted binding",
    );

    let batch = tx.changes().since(home, epoch_of_home, 0, 10).await?;
    let log: Vec<(String, u64, ChangeKind)> = batch
        .changes
        .iter()
        .map(|change| (change.uri.to_string(), change.seq, change.kind))
        .collect();
    checks.equal(
        &log,
        &vec![
            ("projects".to_owned(), 2, ChangeKind::Upsert),
            ("personal".to_owned(), 4, ChangeKind::Delete),
        ],
        "create, create, update and delete advance the home sequence and log the binding slugs (latest per name)",
    );
    checks.equal(&batch.current.seq, &4, "the home sequence");

    let doomed = tx.calendars().get(world.shared).await?;
    tx.calendars().soft_delete(doomed.id, doomed.version).await?;
    checks.equal(
        &tx.bindings().list_for(world.olivia).await?.len(),
        &0,
        "bindings of soft-deleted calendars are skipped",
    );
    tx.commit().await?;
    Ok(())
}

/// Collection properties: shared and per binding.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn collection_properties(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let mine = tx
        .bindings()
        .create(binding(0x501, world.olivia, world.personal, "personal")?)
        .await?;
    let property = |scope: PropertyScope, ns: &str, name: &str, value: &str| CollectionProperty {
        calendar_id: world.personal,
        scope,
        ns: ns.to_owned(),
        name: name.to_owned(),
        value_xml: value.to_owned(),
    };
    let own = PropertyScope::Binding(mine.id);
    tx.properties()
        .set(property(PropertyScope::Shared, "DAV:", "z", "<z/>"))
        .await?;
    tx.properties()
        .set(property(PropertyScope::Shared, "urn:b", "a", "<a/>"))
        .await?;
    tx.properties()
        .set(property(PropertyScope::Shared, "DAV:", "a", "<a1/>"))
        .await?;
    tx.properties().set(property(own, "DAV:", "a", "<private/>")).await?;
    checks.equal(
        &tx.properties()
            .list(world.personal, PropertyScope::Shared)
            .await?
            .iter()
            .map(|found| (found.ns.clone(), found.name.clone()))
            .collect::<Vec<_>>(),
        &vec![
            ("DAV:".to_owned(), "a".to_owned()),
            ("DAV:".to_owned(), "z".to_owned()),
            ("urn:b".to_owned(), "a".to_owned()),
        ],
        "properties are ordered by namespace and name and the scopes are separate",
    );
    checks.equal(
        &tx.properties()
            .get(world.personal, own, "DAV:", "a")
            .await?
            .map(|found| found.value_xml),
        &Some("<private/>".to_owned()),
        "a binding property",
    );
    checks.equal(
        &tx.properties()
            .get(world.personal, PropertyScope::Shared, "DAV:", "a")
            .await?
            .map(|found| found.value_xml),
        &Some("<a1/>".to_owned()),
        "the shared property of the same name",
    );
    checks.equal(
        &tx.properties().get(world.personal, own, "DAV:", "missing").await?,
        &None,
        "a missing property is None",
    );
    tx.properties()
        .set(property(PropertyScope::Shared, "DAV:", "a", "<replaced/>"))
        .await?;
    checks.equal(
        &tx.properties().count(world.personal, PropertyScope::Shared).await?,
        &3,
        "setting replaces",
    );
    checks.equal(
        &tx.properties().count(world.personal, own).await?,
        &1,
        "the count of one scope",
    );
    checks.equal(
        &tx.properties()
            .remove(world.personal, PropertyScope::Shared, "DAV:", "a")
            .await?,
        &true,
        "removing an existing property",
    );
    checks.equal(
        &tx.properties()
            .remove(world.personal, PropertyScope::Shared, "DAV:", "a")
            .await?,
        &false,
        "removing a missing property",
    );
    checks.not_found(
        tx.properties().list(id(0x999), PropertyScope::Shared).await,
        "the properties of an unknown calendar",
    );
    checks.not_found(
        tx.properties()
            .list(world.personal, PropertyScope::Binding(id(0x999)))
            .await,
        "the properties of an unknown binding",
    );
    checks.not_found(
        tx.properties().list(world.shared, own).await,
        "a binding of another calendar",
    );
    checks.not_found(
        tx.properties()
            .set(property(PropertyScope::Binding(id(0x999)), "DAV:", "x", "<x/>"))
            .await,
        "setting on an unknown binding",
    );
    checks.not_found(
        tx.properties().count(id(0x999), PropertyScope::Shared).await,
        "counting on an unknown calendar",
    );
    tx.commit().await?;
    Ok(())
}

/// Grants.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn grants(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let mut invited = grant(0x601, world.shared, world.mia, GrantStatus::Pending);
    invited.invite_uid = Some(key(Uid::parse("invite-123"))?);
    invited.summary = Some("Projects".to_owned());
    invited.common_name = Some("Mia".to_owned());
    let created = tx.grants().create(invited.clone()).await?;
    checks.equal(&created.version, &1, "a new grant has version 1");
    checks.equal(&created.tenant_id, &world.a, "bound to the tenant of the transaction");
    checks.equal(&created.invite_uid, &invited.invite_uid, "the invitation UID is stored");
    checks.equal(&tx.grants().get(created.id).await?, &created, "get");
    checks.equal(
        &tx.grants().find(world.shared, world.mia).await?,
        &Some(created.clone()),
        "find by calendar and grantee",
    );
    checks.equal(
        &tx.grants().find(world.shared, world.olivia).await?,
        &None,
        "no grant for another grantee",
    );
    checks.equal(
        &tx.grants().find_by_invite_uid(&key(Uid::parse("invite-123"))?).await?,
        &Some(created.clone()),
        "find by invitation UID",
    );
    checks.equal(
        &tx.grants().find_by_invite_uid(&key(Uid::parse("nope"))?).await?,
        &None,
        "an unknown invitation",
    );
    tx.grants()
        .create(grant(0x602, world.shared, world.olivia, GrantStatus::Accepted))
        .await?;
    checks.equal(
        &tx.grants()
            .for_calendar(world.shared)
            .await?
            .iter()
            .map(|found| found.id.as_uuid())
            .collect::<Vec<_>>(),
        &vec![super::world::uuid(0x601), super::world::uuid(0x602)],
        "the grants of a calendar in id order",
    );
    tx.grants()
        .create(grant(0x603, world.personal, world.mia, GrantStatus::Accepted))
        .await?;
    tx.grants()
        .create(grant(0x604, world.team_calendar, world.team, GrantStatus::Accepted))
        .await?;
    checks.equal(
        &tx.grants().for_grantee(world.mia).await?.len(),
        &2,
        "the grants given directly to a grantee, not those given to its groups",
    );
    checks.unique(
        tx.grants()
            .create(grant(0x605, world.shared, world.mia, GrantStatus::Accepted))
            .await,
        UniqueKey::Grant,
        "a second grant for the same calendar and grantee",
    );
    checks.not_found(
        tx.grants()
            .create(grant(0x606, id(0x999), world.mia, GrantStatus::Accepted))
            .await,
        "a grant on an unknown calendar",
    );
    checks.not_found(
        tx.grants()
            .create(grant(0x607, world.shared, id(0x999), GrantStatus::Accepted))
            .await,
        "a grant for an unknown grantee",
    );
    checks.not_found(
        tx.grants().for_calendar(id(0x999)).await,
        "the grants of an unknown calendar",
    );

    let mut changed = created.clone();
    changed.access = GrantAccess::Admin;
    changed.status = GrantStatus::Accepted;
    changed.source = GrantSource::Api;
    changed.summary = None;
    changed.common_name = Some("Mia M.".to_owned());
    changed.invite_uid = None;
    changed.required = true;
    checks.equal(
        &created.required,
        &false,
        "a grant is optional unless it says otherwise",
    );
    let updated = tx.grants().update(changed.clone(), created.version).await?;
    checks.equal(&updated.version, &2, "an update bumps the version");
    checks.equal(&updated.required, &true, "the required flag changes");
    checks.equal(
        &tx.grants().get(created.id).await?.required,
        &true,
        "the required flag is stored",
    );
    checks.equal(&updated.access, &GrantAccess::Admin, "the access changes");
    checks.equal(&updated.status, &GrantStatus::Accepted, "the status changes");
    checks.equal(&updated.source, &GrantSource::Api, "the source changes");
    checks.equal(&updated.invite_uid, &None, "the invitation UID changes");
    checks.equal(
        &updated.calendar_id,
        &created.calendar_id,
        "the calendar does not change",
    );
    checks.precondition_failed(
        tx.grants().update(changed.clone(), created.version).await,
        "a stale version",
    );
    checks.not_found(
        tx.grants()
            .update(grant(0x998, world.shared, world.mia, GrantStatus::Accepted), 1)
            .await,
        "an unknown grant",
    );
    tx.grants().delete(created.id).await?;
    checks.not_found(tx.grants().get(created.id).await, "a deleted grant");
    checks.not_found(tx.grants().delete(created.id).await, "deleting twice");
    tx.commit().await?;
    Ok(())
}

/// Soft deletion takes every binding of the calendar with it (the owner's and the sharees', with their private
/// properties), tells the home of each principal, and frees the binding slug together with the calendar's.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn calendars_soft_delete_removes_bindings(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let home = |principal: davhaven_domain::PrincipalId| CollectionKey {
        kind: CollectionKind::Home,
        id: principal.as_uuid(),
    };
    let mut tx = begin(db, world.a).await?;
    let owner_binding = tx
        .bindings()
        .create(binding(0x601, world.olivia, world.shared, "projects")?)
        .await?;
    let sharee_binding = tx
        .bindings()
        .create(binding(0x602, world.mia, world.shared, "olivia-projects")?)
        .await?;
    let survivor = tx
        .bindings()
        .create(binding(0x603, world.mia, world.personal, "olivia-personal")?)
        .await?;
    tx.properties()
        .set(CollectionProperty {
            calendar_id: world.shared,
            scope: PropertyScope::Binding(sharee_binding.id),
            ns: "DAV:".to_owned(),
            name: "displayname".to_owned(),
            value_xml: "<displayname>Mine</displayname>".to_owned(),
        })
        .await?;
    tx.commit().await?;

    let mut tx = begin(db, world.a).await?;
    let olivia_before = tx.changes().state(home(world.olivia)).await?;
    let mia_before = tx.changes().state(home(world.mia)).await?;
    let shared = tx.calendars().get(world.shared).await?;
    tx.calendars().soft_delete(world.shared, shared.version).await?;

    checks.equal(
        &tx.bindings().list_for(world.olivia).await?.len(),
        &0,
        "the owner's binding is gone",
    );
    checks.not_found(tx.bindings().get(owner_binding.id).await, "get of the owner's binding");
    checks.not_found(
        tx.bindings().get(sharee_binding.id).await,
        "get of the sharee's binding",
    );
    checks.equal(
        &tx.bindings()
            .list_for(world.mia)
            .await?
            .iter()
            .map(|bound| bound.binding.id)
            .collect::<Vec<_>>(),
        &vec![survivor.id],
        "the binding of another calendar stays",
    );
    checks.not_found(
        tx.properties()
            .list(world.shared, PropertyScope::Binding(sharee_binding.id))
            .await,
        "the properties private to a deleted binding",
    );

    for (principal, before, name) in [
        (world.olivia, olivia_before, "projects"),
        (world.mia, mia_before, "olivia-projects"),
    ] {
        let batch = tx
            .changes()
            .since(home(principal), before.epoch, before.seq, 10)
            .await?;
        checks.equal(
            &batch
                .changes
                .iter()
                .map(|change| (change.uri.to_string(), change.kind))
                .collect::<Vec<_>>(),
            &vec![(name.to_owned(), ChangeKind::Delete)],
            "the home of the principal logs the disappearing collection",
        );
        checks.equal(&batch.current.seq, &(before.seq + 1), "and advances once for it");
    }

    // The name is free for a new calendar and for its binding, right away (no purge needed).
    let again = tx
        .calendars()
        .create(calendar(0x330, world.olivia, "projects", CalendarKind::User)?)
        .await?;
    let rebound = tx
        .bindings()
        .create(binding(0x604, world.olivia, again.id, "projects")?)
        .await?;
    checks.equal(
        &rebound.slug,
        &owner_binding.slug,
        "the binding slug of a deleted calendar is free again",
    );
    tx.calendars().purge(world.shared).await?;
    checks.equal(
        &tx.bindings().list_for(world.olivia).await?.len(),
        &1,
        "purging the deleted calendar leaves the new binding alone",
    );
    tx.commit().await?;
    Ok(())
}

/// The batch reads of the calendar repositories (`BindingRepo::find_for_calendars`, `PropertyRepo::list_many` and
/// `GrantRepo::for_calendars`) answer exactly what the single reads answer, in the order the contract names.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn calendars_batch_reads(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    // Every calendar of the world is listed by its owner; Mia lists two of them as a sharee and a group member.
    let personal_of_owner = tx
        .bindings()
        .create(binding(0x501, world.olivia, world.personal, "personal")?)
        .await?;
    let shared_of_owner = tx
        .bindings()
        .create(binding(0x502, world.olivia, world.shared, "projects")?)
        .await?;
    let shared_of_mia = tx
        .bindings()
        .create(binding(0x503, world.mia, world.shared, "projects-of-olivia")?)
        .await?;
    let team_of_owner = tx
        .bindings()
        .create(binding(0x504, world.team, world.team_calendar, "team-calendar")?)
        .await?;
    // A calendar whose owner has no binding for it.
    let orphan = tx
        .calendars()
        .create(calendar(0x304, world.mia, "unlisted", CalendarKind::User)?)
        .await?;

    let listed = [
        (world.team, world.team_calendar),
        (world.mia, world.shared),
        (world.olivia, world.personal),
        (world.mia, orphan.id),
        (world.olivia, world.shared),
        (world.olivia, world.personal),
        (world.mia, orphan.id),
        (world.gina, world.personal),
    ];
    checks.equal(
        &tx.bindings()
            .find_for_calendars(&listed)
            .await?
            .iter()
            .map(|found| found.id)
            .collect::<Vec<_>>(),
        &vec![
            personal_of_owner.id,
            shared_of_owner.id,
            shared_of_mia.id,
            team_of_owner.id,
        ],
        "find_for_calendars: the bindings that exist, by calendar id and then principal id, nothing for a pair \
         without a binding, a repeated pair once",
    );
    for (principal, calendar) in listed {
        let single = tx.bindings().find_for_calendar(principal, calendar).await?;
        let batch = tx.bindings().find_for_calendars(&[(principal, calendar)]).await?;
        checks.equal(
            &batch,
            &single.into_iter().collect::<Vec<_>>(),
            "find_for_calendars agrees with find_for_calendar for one pair",
        );
    }
    checks.equal(
        &tx.bindings().find_for_calendars(&[]).await?.len(),
        &0,
        "find_for_calendars without pairs",
    );
    let hidden = tx.bindings().get(shared_of_mia.id).await?;
    tx.bindings()
        .update(
            davhaven_domain::Binding {
                hidden: true,
                ..hidden.clone()
            },
            hidden.version,
        )
        .await?;
    checks.equal(
        &tx.bindings()
            .find_for_calendars(&[(world.mia, world.shared)])
            .await?
            .iter()
            .map(|found| (found.id, found.hidden))
            .collect::<Vec<_>>(),
        &vec![(shared_of_mia.id, true)],
        "find_for_calendars includes hidden bindings, as find_for_calendar does",
    );

    // Properties: shared ones of the calendar and the ones private to the binding.
    let property = |calendar_id, scope: PropertyScope, name: &str| CollectionProperty {
        calendar_id,
        scope,
        ns: "DAV:".to_owned(),
        name: name.to_owned(),
        value_xml: format!("<{name}/>"),
    };
    for set in [
        property(world.personal, PropertyScope::Shared, "shared-personal"),
        property(
            world.personal,
            PropertyScope::Binding(personal_of_owner.id),
            "own-personal",
        ),
        property(world.shared, PropertyScope::Shared, "shared-projects"),
        property(
            world.shared,
            PropertyScope::Binding(shared_of_owner.id),
            "owners-projects",
        ),
        property(world.shared, PropertyScope::Binding(shared_of_mia.id), "mias-projects"),
        property(world.shared, PropertyScope::Binding(shared_of_mia.id), "also-mias"),
        property(
            world.team_calendar,
            PropertyScope::Binding(team_of_owner.id),
            "own-team",
        ),
    ] {
        tx.properties().set(set).await?;
    }
    let pairs = [
        (world.team_calendar, team_of_owner.id),
        (world.shared, shared_of_mia.id),
        (world.personal, personal_of_owner.id),
    ];
    let mut expected = Vec::new();
    for (calendar, binding) in [
        (world.personal, personal_of_owner.id),
        (world.shared, shared_of_mia.id),
        (world.team_calendar, team_of_owner.id),
    ] {
        expected.extend(tx.properties().list(calendar, PropertyScope::Shared).await?);
        expected.extend(tx.properties().list(calendar, PropertyScope::Binding(binding)).await?);
    }
    let found = tx.properties().list_many(&pairs).await?;
    checks.equal(
        &found,
        &expected,
        "list_many: by calendar id, the shared properties first and then the binding's own, each in the order of list",
    );
    checks.that(
        !found.iter().any(|found| found.name == "owners-projects"),
        "list_many leaves out the properties of bindings it was not asked for",
    );
    // A pair whose binding belongs to another calendar, a calendar that does not exist and a second binding of a
    // calendar that is listed already: the first two contribute nothing, the last one adds its own properties only.
    let odd = tx
        .properties()
        .list_many(&[
            (world.personal, shared_of_mia.id),
            (id(0x999), personal_of_owner.id),
            (world.shared, shared_of_mia.id),
            (world.shared, shared_of_owner.id),
            (world.shared, shared_of_mia.id),
        ])
        .await?;
    let names: Vec<&str> = odd.iter().map(|found| found.name.as_str()).collect();
    checks.equal(
        &names,
        &vec!["shared-projects", "owners-projects", "also-mias", "mias-projects"],
        "list_many: invalid pairs contribute nothing and the shared properties of a calendar come once",
    );
    checks.equal(
        &tx.properties().list_many(&[]).await?.len(),
        &0,
        "list_many without bindings",
    );

    // Grants.
    let to_mia = tx
        .grants()
        .create(grant(0x601, world.shared, world.mia, GrantStatus::Accepted))
        .await?;
    let pending = tx
        .grants()
        .create(grant(0x602, world.personal, world.mia, GrantStatus::Pending))
        .await?;
    let to_olivia = tx
        .grants()
        .create(grant(0x603, world.team_calendar, world.olivia, GrantStatus::Declined))
        .await?;
    let second = tx
        .grants()
        .create(grant(0x604, world.shared, world.team, GrantStatus::Accepted))
        .await?;
    checks.equal(
        &tx.grants()
            .for_calendars(&[
                world.team_calendar,
                world.shared,
                id(0x999),
                world.personal,
                world.shared,
            ])
            .await?
            .iter()
            .map(|found| found.id)
            .collect::<Vec<_>>(),
        &vec![pending.id, to_mia.id, second.id, to_olivia.id],
        "for_calendars: by calendar id and then grant id, pending and declined grants included, unknown calendars \
         skipped, a repeated calendar once",
    );
    checks.equal(
        &tx.grants().for_calendars(&[]).await?.len(),
        &0,
        "for_calendars without calendars",
    );
    let doomed = tx.calendars().get(world.shared).await?;
    tx.calendars().soft_delete(doomed.id, doomed.version).await?;
    checks.equal(
        &tx.grants().for_calendars(&[world.shared]).await?.len(),
        &0,
        "for_calendars skips a soft-deleted calendar, as for_calendar answers NotFound for it",
    );
    checks.equal(
        &tx.bindings()
            .find_for_calendars(&listed)
            .await?
            .iter()
            .map(|found| found.id)
            .collect::<Vec<_>>(),
        &vec![personal_of_owner.id, team_of_owner.id],
        "find_for_calendars finds nothing of a soft-deleted calendar: its bindings went with it",
    );
    tx.commit().await?;
    Ok(())
}
