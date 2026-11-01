//! Cases of the system tenant repository.

use davhaven_domain::audit::TenantSettingsAudit;
use davhaven_domain::{AuditActor, AuditEvent, CollectionKey, CollectionKind, Locale, TenantSettings, TenantStatus};
use davhaven_ports::{AuditFilter, NewAudit, NewTenantAudit, PageReq, TenantAudit, UniqueKey};

use super::Outcome;
use super::world::{
    Db, StoreChecks, begin, calendar, epoch, far_future, id, key, long_ago, principal, seed, system, tenant, uuid,
};
use crate::suite::Checks;
use davhaven_domain::{CalendarKind, DomainName, PrincipalKind};

/// Creating, reading, finding and listing tenants.
pub(super) async fn tenants_create_get_find_list(db: &Db, checks: &mut Checks) -> Outcome {
    let mut tx = system(db).await?;
    let acme = tx.tenants().create(tenant(1, "acme", Some("acme.example"))?).await?;
    let globex = tx.tenants().create(tenant(2, "globex", None)?).await?;
    checks.equal(&acme.version, &1, "a new tenant has version 1 whatever the entity said");
    checks.equal(&acme.created_at, &acme.updated_at, "creation stamps both times alike");
    checks.that(acme.created_at != epoch(), "the store stamps created_at itself");
    checks.equal(
        &tx.tenants().get(acme.id).await?,
        &acme,
        "get returns what create returned",
    );
    checks.equal(
        &tx.tenants().find_by_slug(&acme.slug).await?,
        &Some(acme.clone()),
        "find by slug",
    );
    let domain = key(DomainName::parse("acme.example"))?;
    checks.equal(
        &tx.tenants().find_by_login_domain(&domain).await?,
        &Some(acme.clone()),
        "find by login domain",
    );
    let other_domain = key(DomainName::parse("nowhere.example"))?;
    checks.equal(
        &tx.tenants().find_by_login_domain(&other_domain).await?,
        &None,
        "an unknown login domain finds nothing",
    );
    checks.equal(
        &tx.tenants().find_by_slug(&globex.slug).await?.map(|found| found.id),
        &Some(globex.id),
        "globex",
    );
    checks.not_found(tx.tenants().get(id(99)).await, "an unknown tenant");

    let first = tx.tenants().list(PageReq::first(1)).await?;
    checks.equal(
        &first.items,
        &vec![acme.clone()],
        "the first page holds the first tenant",
    );
    checks.equal(&first.next, &Some(acme.id.as_uuid()), "and names it as the cursor");
    let second = tx.tenants().list(PageReq::first(1).after(acme.id.as_uuid())).await?;
    checks.equal(
        &second.items,
        &vec![globex.clone()],
        "the second page holds the second tenant",
    );
    checks.equal(&second.next, &None, "and is the last");
    tx.commit().await?;

    let mut own = begin(db, acme.id).await?;
    checks.equal(
        &own.tenant().get().await?,
        &acme,
        "a tenant transaction reads its own row",
    );
    checks.equal(&own.tenant_id(), &acme.id, "and reports its tenant");
    Ok(())
}

/// Updating and deleting tenants.
pub(super) async fn tenants_update_and_delete(db: &Db, checks: &mut Checks) -> Outcome {
    let mut tx = system(db).await?;
    let created = tx.tenants().create(tenant(1, "acme", Some("acme.example"))?).await?;
    let mut changed = tenant(1, "renamed", Some("new.example"))?;
    changed.display_name = "Acme Inc".into();
    changed.status = TenantStatus::Suspended;
    let mut settings = TenantSettings::default();
    settings.theme = Some("dark".into());
    settings.busy_text = Some("In a meeting".into());
    settings.busy_text_by_locale = [("de", "Nicht verfügbar"), ("en-GB", "Out")]
        .into_iter()
        .map(|(tag, text)| Ok((key(Locale::parse(tag))?, text.to_owned())))
        .collect::<Result<_, davhaven_ports::StoreError>>()?;
    changed.settings = settings.clone();
    let updated = tx.tenants().update(changed.clone(), created.version).await?;
    checks.equal(&updated.version, &2, "an update bumps the version");
    checks.equal(&updated.slug, &created.slug, "the slug never changes");
    checks.equal(&updated.display_name.as_str(), &"Acme Inc", "the display name changes");
    checks.equal(&updated.status, &TenantStatus::Suspended, "the status changes");
    checks.equal(&updated.settings.theme.as_deref(), &Some("dark"), "the settings change");
    checks.equal(
        &updated.settings,
        &settings,
        "the settings come back as they were written, the texts per language included",
    );
    checks.equal(
        &tx.tenants().get(created.id).await?.settings,
        &settings,
        "and are read from the store as they were written",
    );
    checks.equal(
        &updated.login_domain.as_ref().map(DomainName::as_str),
        &Some("new.example"),
        "the login domain changes",
    );
    checks.equal(&updated.created_at, &created.created_at, "creation time stays");
    checks.that(
        updated.updated_at >= created.updated_at,
        "the update time does not go back",
    );
    checks.precondition_failed(
        tx.tenants().update(changed.clone(), created.version).await,
        "a stale version",
    );
    checks.not_found(
        tx.tenants().update(tenant(77, "ghost", None)?, 1).await,
        "an unknown tenant",
    );
    tx.commit().await?;

    let mut tenant_tx = begin(db, created.id).await?;
    tenant_tx
        .principals()
        .create(principal(5, "ann", PrincipalKind::User)?)
        .await?;
    let owner = id(5);
    tenant_tx
        .calendars()
        .create(calendar(6, owner, "cal", CalendarKind::User)?)
        .await?;
    tenant_tx.commit().await?;

    let mut tx = system(db).await?;
    tx.tenants().delete(created.id).await?;
    checks.equal(
        &tx.tenants().find_by_slug(&created.slug).await?,
        &None,
        "the tenant is gone",
    );
    checks.not_found(tx.tenants().delete(created.id).await, "deleting twice");
    tx.commit().await?;

    let mut gone = begin(db, created.id).await?;
    checks.not_found(gone.tenant().get().await, "the tenant row of a deleted tenant");
    checks.not_found(gone.principals().get(owner).await, "the principals of a deleted tenant");
    checks.not_found(gone.calendars().get(id(6)).await, "the calendars of a deleted tenant");
    Ok(())
}

/// Tenant slugs and login domains are unique, and a violation leaves the transaction usable.
pub(super) async fn tenants_unique_keys(db: &Db, checks: &mut Checks) -> Outcome {
    let mut tx = system(db).await?;
    tx.tenants().create(tenant(1, "acme", Some("acme.example"))?).await?;
    checks.unique(
        tx.tenants().create(tenant(2, "acme", None)?).await,
        UniqueKey::TenantSlug,
        "a duplicate slug",
    );
    checks.unique(
        tx.tenants().create(tenant(3, "other", Some("ACME.example"))?).await,
        UniqueKey::LoginDomain,
        "a duplicate login domain (case-insensitive)",
    );
    let globex = tx
        .tenants()
        .create(tenant(4, "globex", Some("globex.example"))?)
        .await?;
    checks.equal(
        &globex.slug.as_str(),
        &"globex",
        "the transaction is usable after violations",
    );
    checks.unique(
        tx.tenants()
            .update(tenant(4, "globex", Some("acme.example"))?, globex.version)
            .await,
        UniqueKey::LoginDomain,
        "updating to a taken login domain",
    );
    checks.equal(
        &tx.tenants()
            .get(globex.id)
            .await?
            .login_domain
            .map(|domain| domain.to_string()),
        &Some("globex.example".to_owned()),
        "a failed update changes nothing",
    );
    tx.commit().await?;
    Ok(())
}

/// The audit log of a deleted tenant stays until retention removes it.
pub(super) async fn tenants_delete_keeps_the_audit_log(db: &Db, checks: &mut Checks) -> Outcome {
    let mut tx = system(db).await?;
    let created = tx.tenants().create(tenant(1, "acme", None)?).await?;
    tx.commit().await?;
    let mut tenant_tx = begin(db, created.id).await?;
    tenant_tx
        .audit()
        .append(NewAudit {
            id: uuid(1),
            actor: AuditActor::system(),
            event: AuditEvent::TenantDeleted,
        })
        .await?;
    tenant_tx.commit().await?;
    let mut tx = system(db).await?;
    tx.tenants().delete(created.id).await?;
    tx.commit().await?;
    let mut tenant_tx = begin(db, created.id).await?;
    let page = tenant_tx
        .audit()
        .list(&AuditFilter::default(), PageReq::default())
        .await?;
    checks.equal(&page.items.len(), &1, "the record of the deletion outlives the tenant");
    checks.equal(
        &page.items.first().map(|row| row.action.as_str()),
        &Some("tenant.deleted"),
        "and says what happened",
    );
    Ok(())
}

/// A system transaction appends the audit records of tenant management (`tenant.created`, `tenant.settings_changed`)
/// to the log of the tenant: they commit and roll back with the change, and the tenant has to exist. Nothing else can
/// be recorded from system scope: the signature takes the two events and no other.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn tenants_audit_in_the_system_transaction(db: &Db, checks: &mut Checks) -> Outcome {
    let record = |n: u128, event: TenantAudit| NewTenantAudit {
        id: uuid(n),
        actor: AuditActor::system(),
        event,
    };
    let list = |tenant| async move {
        let mut tx = begin(db, tenant).await?;
        let page = tx.audit().list(&AuditFilter::default(), PageReq::default()).await?;
        Ok::<_, davhaven_ports::StoreError>(page.items)
    };

    // The record commits together with the tenant it describes, and the tenant sees it.
    let mut tx = system(db).await?;
    let acme = tx.tenants().create(tenant(1, "acme", None)?).await?;
    let globex = tx.tenants().create(tenant(2, "globex", None)?).await?;
    tx.tenants()
        .append_audit(acme.id, record(1, TenantAudit::Created))
        .await?;
    tx.commit().await?;
    let rows = list(acme.id).await?;
    checks.equal(
        &rows.iter().map(|row| (row.id, row.action.as_str())).collect::<Vec<_>>(),
        &vec![(uuid(1), "tenant.created")],
        "a record appended in the system transaction is in the log of the tenant",
    );
    checks.equal(
        &rows
            .first()
            .map(|row| (row.tenant_id, row.actor.clone(), row.target.clone())),
        &Some((acme.id, AuditActor::system(), None)),
        "with its tenant and its actor, and no target",
    );
    checks.that(
        rows.first()
            .is_some_and(|row| row.at >= long_ago() && row.at < far_future()),
        "stamped by the clock of the store",
    );
    checks.equal(&list(globex.id).await?.len(), &0, "and in no other tenant's log");

    // The settings event carries its details, and the record is rolled back with the transaction.
    let mut tx = system(db).await?;
    tx.tenants()
        .append_audit(
            acme.id,
            record(
                2,
                TenantAudit::SettingsChanged(TenantSettingsAudit {
                    fields: vec!["display_name".to_owned()],
                }),
            ),
        )
        .await?;
    drop(tx);
    checks.equal(
        &list(acme.id).await?.len(),
        &1,
        "a record is rolled back with its transaction",
    );
    let mut tx = system(db).await?;
    tx.tenants()
        .append_audit(
            acme.id,
            record(
                2,
                TenantAudit::SettingsChanged(TenantSettingsAudit {
                    fields: vec!["display_name".to_owned()],
                }),
            ),
        )
        .await?;
    tx.commit().await?;
    let rows = list(acme.id).await?;
    checks.equal(
        &rows.iter().map(|row| row.action.as_str()).collect::<Vec<_>>(),
        &vec!["tenant.created", "tenant.settings_changed"],
        "the settings event is recorded too, in id order",
    );
    checks.equal(
        &rows.get(1).map(|row| row.details.clone()),
        &Some(serde_json::json!({"fields": ["display_name"]})),
        "with the names of the fields",
    );

    // Refusals leave the transaction usable and change nothing.
    let mut tx = system(db).await?;
    checks.not_found(
        tx.tenants()
            .append_audit(id(0xDEAD), record(3, TenantAudit::Created))
            .await,
        "a tenant that does not exist",
    );
    checks.internal(
        tx.tenants()
            .append_audit(acme.id, record(1, TenantAudit::Created))
            .await,
        "an id that exists",
    );
    tx.tenants()
        .append_audit(globex.id, record(4, TenantAudit::Created))
        .await?;
    tx.commit().await?;
    checks.equal(
        &list(acme.id).await?.len(),
        &2,
        "a refused record leaves the log of the tenant as it was",
    );
    checks.equal(
        &list(globex.id).await?.iter().map(|row| row.id).collect::<Vec<_>>(),
        &vec![uuid(4)],
        "and the transaction went on with the next one",
    );
    Ok(())
}

/// A new sync epoch invalidates every outstanding sync token of the tenant (or of all tenants).
pub(super) async fn tenants_bump_the_sync_epoch(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let calendar = CollectionKey {
        kind: CollectionKind::Calendar,
        id: world.personal.as_uuid(),
    };
    let home = CollectionKey {
        kind: CollectionKind::Home,
        id: world.olivia.as_uuid(),
    };
    let gina_home = CollectionKey {
        kind: CollectionKind::Home,
        id: world.gina.as_uuid(),
    };
    let mut tx = begin(db, world.a).await?;
    let before = tx.changes().state(calendar).await?;
    let home_before = tx.changes().state(home).await?;
    tx.commit().await?;
    let mut other = begin(db, world.b).await?;
    let gina_before = other.changes().state(gina_home).await?;
    drop(other);

    let mut system_tx = system(db).await?;
    let changed = system_tx.tenants().bump_sync_epoch(Some(world.a)).await?;
    checks.equal(
        &changed,
        &12,
        "three calendars and three principals with three collections each",
    );
    checks.not_found(
        system_tx.tenants().bump_sync_epoch(Some(id(0xDEAD))).await,
        "an unknown tenant",
    );
    system_tx.commit().await?;

    let mut tx = begin(db, world.a).await?;
    let after = tx.changes().state(calendar).await?;
    checks.differ(&after.epoch, &before.epoch, "the calendar has a new epoch");
    checks.equal(&after.seq, &before.seq, "the sequence continues");
    checks.differ(
        &tx.changes().state(home).await?.epoch,
        &home_before.epoch,
        "the home has a new epoch",
    );
    let stale = tx.changes().since(calendar, before.epoch, before.seq, 10).await;
    checks.invalid_sync_token(stale, "a token of the old epoch");
    let fresh = tx.changes().since(calendar, after.epoch, after.seq, 10).await?;
    checks.that(
        fresh.changes.is_empty() && !fresh.truncated,
        "a token of the new epoch works",
    );
    drop(tx);
    let mut other = begin(db, world.b).await?;
    checks.equal(
        &other.changes().state(gina_home).await?.epoch,
        &gina_before.epoch,
        "another tenant keeps its epoch",
    );
    drop(other);

    let mut system_tx = system(db).await?;
    checks.equal(&system_tx.tenants().bump_sync_epoch(None).await?, &15, "all tenants");
    system_tx.commit().await?;
    let mut other = begin(db, world.b).await?;
    checks.differ(
        &other.changes().state(gina_home).await?.epoch,
        &gina_before.epoch,
        "now the other tenant has a new epoch too",
    );
    Ok(())
}
