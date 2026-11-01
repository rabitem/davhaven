//! Cases of the outbox, webhooks, provider accounts and OAuth states.

use std::time::Duration;

use davhaven_domain::{
    CalendarId, DeliveryId, EventId, EventType, ExternalAccount, ExternalAccountId, ExternalAccountStatus, ItipMethod,
    ObjectId, PrincipalId, WebhookId, WebhookSubscription,
};
use davhaven_ports::DeliveryJob;
use davhaven_ports::{
    DeliveryRecord, DeliveryStatus, ExternalAccountFilter, NewOutbox, OAuthState, OutboxClaim, OutboxFailure,
    OutboxFilter, OutboxKey, OutboxMessage, OutboxRecord, OutboxStatus, PageReq, Reserved, UniqueKey,
};

use super::Outcome;
use super::world::{Db, StoreChecks, begin, epoch, far_future, id, key, long_ago, nobody, seed, system, uuid};
use crate::suite::Checks;

/// The outbox message of the suite: a reserved provider push.
fn push() -> OutboxMessage {
    OutboxMessage::ProviderPush(Reserved {})
}

/// An internal delivery job for the calendar.
fn delivery_job(calendar: CalendarId, recipient: PrincipalId) -> OutboxMessage {
    OutboxMessage::InternalDelivery(DeliveryJob {
        calendar,
        object: id::<ObjectId>(0x4F1),
        method: ItipMethod::Request,
        recipients: vec![recipient],
        snapshot: None,
        copy_only: false,
    })
}

/// Enqueueing, reading, listing and requeueing outbox records.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn outbox_inspection(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    tx.outbox().enqueue(NewOutbox::now(id(0xA01), push())).await?;
    tx.outbox()
        .enqueue(NewOutbox::at(
            id(0xA02),
            delivery_job(world.personal, world.mia),
            far_future(),
        ))
        .await?;
    let first = tx.outbox().get(id(0xA01)).await?;
    checks.equal(&first.status, &OutboxStatus::Pending, "a new record is pending");
    checks.equal(&first.attempts, &0, "without attempts");
    checks.equal(&first.kind.as_str(), &"provider_push", "its kind");
    checks.equal(&first.schema_version, &1, "its payload schema version");
    checks.equal(&first.tenant_id, &world.a, "bound to the tenant of the transaction");
    checks.equal(&first.locked_until, &None, "not locked");
    checks.equal(&first.last_error, &None, "without error");
    checks.equal(&first.created_at, &first.updated_at, "creation stamps both times alike");
    checks.that(
        first.next_attempt_at != epoch() && first.next_attempt_at < far_future(),
        "due now",
    );
    checks.equal(
        &first.message().ok(),
        &Some(push()),
        "the payload decodes to the message",
    );
    let second = tx.outbox().get(id(0xA02)).await?;
    checks.equal(&second.next_attempt_at, &far_future(), "not_before sets the due time");
    checks.equal(
        &second.message().ok(),
        &Some(delivery_job(world.personal, world.mia)),
        "another payload",
    );
    checks.internal(
        tx.outbox().enqueue(NewOutbox::now(id(0xA01), push())).await,
        "enqueueing an id that exists",
    );
    checks.not_found(tx.outbox().get(id(0x999)).await, "an unknown record");

    let pending = tx
        .outbox()
        .list(
            &OutboxFilter {
                status: Some(OutboxStatus::Pending),
                ..OutboxFilter::default()
            },
            PageReq::default(),
        )
        .await?;
    checks.equal(&pending.items.len(), &2, "the status filter");
    let by_kind = tx
        .outbox()
        .list(
            &OutboxFilter {
                kind: Some("internal_delivery".to_owned()),
                ..OutboxFilter::default()
            },
            PageReq::default(),
        )
        .await?;
    checks.equal(
        &by_kind.items.iter().map(|record| record.id).collect::<Vec<_>>(),
        &vec![second.id],
        "the kind filter",
    );
    let page = tx.outbox().list(&OutboxFilter::default(), PageReq::first(1)).await?;
    checks.equal(
        &page.items.iter().map(|record| record.id).collect::<Vec<_>>(),
        &vec![first.id],
        "the first page",
    );
    checks.equal(&page.next, &Some(first.id.as_uuid()), "with a cursor");
    checks.equal(
        &tx.outbox()
            .list(&OutboxFilter::default(), PageReq::first(1).after(first.id.as_uuid()))
            .await?
            .items
            .len(),
        &1,
        "the second page",
    );
    checks.precondition_failed(
        tx.outbox().requeue(first.id).await,
        "requeueing a record that is not dead",
    );
    checks.not_found(tx.outbox().requeue(id(0x999)).await, "requeueing an unknown record");
    tx.commit().await?;

    let mut sys = system(db).await?;
    let claimed = sys.outbox_claim().claim(10, Duration::from_secs(60)).await?;
    checks.equal(
        &claimed.iter().map(|record| record.id).collect::<Vec<_>>(),
        &vec![first.id],
        "only the due record is claimed",
    );
    sys.outbox_claim()
        .fail(
            OutboxKey {
                tenant: world.a,
                id: first.id,
            },
            OutboxFailure::dead("gave up"),
        )
        .await?;
    sys.commit().await?;
    let mut tx = begin(db, world.a).await?;
    tx.outbox().requeue(first.id).await?;
    let again = tx.outbox().get(first.id).await?;
    checks.equal(
        &again.status,
        &OutboxStatus::Pending,
        "a requeued record is pending again",
    );
    checks.equal(&again.attempts, &0, "with its attempts reset");
    checks.equal(&again.locked_until, &None, "and no lock");
    tx.commit().await?;
    Ok(())
}

/// Claiming, settling and releasing outbox records across tenants.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn outbox_claims(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    for n in [0xA01, 0xA02, 0xA03] {
        tx.outbox().enqueue(NewOutbox::now(id(n), push())).await?;
    }
    tx.outbox()
        .enqueue(NewOutbox::at(id(0xA04), push(), far_future()))
        .await?;
    tx.outbox()
        .enqueue(NewOutbox::at(id(0xA05), push(), long_ago()))
        .await?;
    tx.commit().await?;
    let mut other = begin(db, world.b).await?;
    other.outbox().enqueue(NewOutbox::now(id(0xA06), push())).await?;
    other.commit().await?;

    let ids =
        |records: &[davhaven_ports::OutboxRecord]| records.iter().map(|record| record.id.as_uuid()).collect::<Vec<_>>();
    let mut sys = system(db).await?;
    let first = sys.outbox_claim().claim(2, Duration::from_secs(600)).await?;
    checks.equal(
        &ids(&first),
        &vec![uuid(0xA05), uuid(0xA01)],
        "the oldest due records first, then by id",
    );
    checks.that(
        first
            .iter()
            .all(|record| record.status == OutboxStatus::InFlight && record.attempts == 1),
        "claimed records are in flight with one attempt",
    );
    checks.that(
        first
            .iter()
            .all(|record| record.locked_until.is_some_and(|until| until > record.updated_at)),
        "and locked",
    );
    let second = sys.outbox_claim().claim(10, Duration::from_secs(600)).await?;
    checks.equal(
        &ids(&second),
        &vec![uuid(0xA02), uuid(0xA03), uuid(0xA06)],
        "a record is held by one claimant: the rest comes next, across tenants, the future one stays",
    );
    checks.equal(
        &sys.outbox_claim().claim(10, Duration::from_secs(600)).await?.len(),
        &0,
        "nothing is left to claim",
    );
    checks.equal(
        &sys.outbox_claim().claim(0, Duration::from_secs(600)).await?.len(),
        &0,
        "a limit of zero claims nothing",
    );
    let stats = sys.outbox_claim().stats().await?;
    checks.equal(
        &(stats.pending, stats.in_flight, stats.dead),
        &(1, 5, 0),
        "the queue depth",
    );
    checks.equal(
        &stats.oldest_pending_at,
        &Some(far_future()),
        "the oldest pending record",
    );

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
            OutboxFailure::retry("temporary", far_future()),
        )
        .await?;
    sys.outbox_claim()
        .fail(
            OutboxKey {
                tenant: world.a,
                id: id(0xA03),
            },
            OutboxFailure::dead("permanent"),
        )
        .await?;
    checks.not_found(
        sys.outbox_claim()
            .complete(OutboxKey {
                tenant: world.a,
                id: id(0x999),
            })
            .await,
        "completing an unknown record",
    );
    checks.not_found(
        sys.outbox_claim()
            .fail(
                OutboxKey {
                    tenant: world.b,
                    id: id(0xA01),
                },
                OutboxFailure::dead("x"),
            )
            .await,
        "failing a record under the wrong tenant",
    );
    sys.commit().await?;

    let mut tx = begin(db, world.a).await?;
    let done = tx.outbox().get(id(0xA01)).await?;
    checks.equal(&done.status, &OutboxStatus::Done, "a completed record is done");
    checks.equal(&done.locked_until, &None, "and unlocked");
    let retry = tx.outbox().get(id(0xA02)).await?;
    checks.equal(
        &retry.status,
        &OutboxStatus::Pending,
        "a failed record with a retry time is pending again",
    );
    checks.equal(&retry.next_attempt_at, &far_future(), "due at that time");
    checks.equal(&retry.attempts, &1, "its attempt is counted");
    checks.equal(&retry.last_error.as_deref(), &Some("temporary"), "with the error");
    let dead = tx.outbox().get(id(0xA03)).await?;
    checks.equal(
        &dead.status,
        &OutboxStatus::Dead,
        "a failed record without a retry time is dead",
    );
    checks.equal(&dead.last_error.as_deref(), &Some("permanent"), "with the error");
    tx.commit().await?;

    let mut tx = begin(db, world.a).await?;
    tx.outbox().enqueue(NewOutbox::now(id(0xA07), push())).await?;
    tx.commit().await?;
    let mut sys = system(db).await?;
    let first = sys.outbox_claim().claim(1, Duration::ZERO).await?;
    checks.equal(&ids(&first), &vec![uuid(0xA07)], "a record with a zero lease");
    let reclaimed = sys.outbox_claim().claim(1, Duration::ZERO).await?;
    checks.equal(
        &ids(&reclaimed),
        &vec![uuid(0xA07)],
        "is claimable again at once: the lease is over",
    );
    checks.equal(
        &reclaimed.first().map(|record| record.attempts),
        &Some(2),
        "and the attempt is counted",
    );

    let held = [
        OutboxKey {
            tenant: world.a,
            id: id(0xA05),
        },
        OutboxKey {
            tenant: world.a,
            id: id(0xA07),
        },
        OutboxKey {
            tenant: world.a,
            id: id(0xA01),
        },
        OutboxKey {
            tenant: world.a,
            id: id(0x999),
        },
    ];
    checks.equal(
        &sys.outbox_claim().release_leases(&held).await?,
        &2,
        "releasing counts the records that were in flight",
    );
    sys.commit().await?;
    let mut tx = begin(db, world.a).await?;
    let released = tx.outbox().get(id(0xA05)).await?;
    checks.equal(&released.status, &OutboxStatus::Pending, "a released record is pending");
    checks.equal(
        &released.attempts,
        &0,
        "and the attempt that never finished is not counted",
    );
    checks.equal(&released.locked_until, &None, "without a lock");
    checks.equal(
        &tx.outbox().get(id(0xA07)).await?.attempts,
        &1,
        "(the earlier attempt of the other stays)",
    );
    drop(tx);
    let mut sys = system(db).await?;
    let again = sys.outbox_claim().claim(10, Duration::from_secs(60)).await?;
    checks.equal(
        &ids(&again),
        &vec![uuid(0xA05), uuid(0xA07)],
        "released records are due immediately",
    );
    Ok(())
}

/// A webhook subscription.
pub(super) fn subscription_for(
    n: u128,
    events: &[EventType],
) -> Result<WebhookSubscription, davhaven_ports::StoreError> {
    Ok(WebhookSubscription {
        id: id::<WebhookId>(n),
        tenant_id: nobody(),
        url: key(url::Url::parse("https://hooks.example.org/in"))?,
        description: Some("CRM".to_owned()),
        sealed_secret: vec![1, 2, 3],
        sealed_secret_previous: None,
        secret_rotated_at: None,
        events: events.to_vec(),
        include_details: false,
        active: true,
        failure_count: 0,
        disabled_reason: None,
        created_at: epoch(),
        updated_at: epoch(),
        version: 99,
    })
}

/// A delivery of an event to a subscription.
pub(super) fn delivery_for(n: u128, subscription: WebhookId) -> DeliveryRecord {
    DeliveryRecord {
        id: id::<DeliveryId>(n),
        tenant_id: nobody(),
        subscription_id: subscription,
        event_id: id::<EventId>(n + 0x1000),
        status: DeliveryStatus::Pending,
        attempts: 0,
        response_status: None,
        last_error: None,
        at: epoch(),
        created_at: epoch(),
        updated_at: epoch(),
        version: 99,
    }
}

/// Webhook subscriptions, their failure counters and their deliveries.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn webhooks_and_deliveries(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let events = [EventType::PrincipalCreated, EventType::CalendarObjectsChanged];
    let created = tx.webhooks().create(subscription_for(0xB01, &events)?).await?;
    checks.equal(&created.version, &1, "a new subscription has version 1");
    checks.equal(&created.tenant_id, &world.a, "bound to the tenant of the transaction");
    checks.equal(&created.events, &events.to_vec(), "its events");
    checks.equal(
        &created.sealed_secret,
        &vec![1, 2, 3],
        "the sealed secret is stored as given",
    );
    checks.equal(&tx.webhooks().get(created.id).await?, &created, "get");
    let mut inactive = subscription_for(0xB02, &[EventType::PrincipalCreated])?;
    inactive.active = false;
    let inactive = tx.webhooks().create(inactive).await?;
    checks.equal(
        &tx.webhooks()
            .list(PageReq::default())
            .await?
            .items
            .iter()
            .map(|found| found.id)
            .collect::<Vec<_>>(),
        &vec![created.id, inactive.id],
        "list in id order",
    );
    checks.equal(
        &tx.webhooks()
            .subscribed_to(EventType::PrincipalCreated)
            .await?
            .iter()
            .map(|found| found.id)
            .collect::<Vec<_>>(),
        &vec![created.id],
        "active subscriptions to an event type",
    );
    checks.equal(
        &tx.webhooks().subscribed_to(EventType::CalendarCreated).await?.len(),
        &0,
        "none for another type",
    );
    checks.not_found(tx.webhooks().get(id(0x999)).await, "an unknown subscription");

    let mut changed = created.clone();
    changed.url = key(url::Url::parse("https://other.example.org/hook"))?;
    changed.events = vec![EventType::CalendarCreated];
    changed.include_details = true;
    changed.sealed_secret_previous = Some(vec![9]);
    changed.secret_rotated_at = Some(far_future());
    let updated = tx.webhooks().update(changed.clone(), created.version).await?;
    checks.equal(&updated.version, &2, "an update bumps the version");
    checks.equal(
        &updated.url.as_str(),
        &"https://other.example.org/hook",
        "the URL changes",
    );
    checks.equal(&updated.events, &vec![EventType::CalendarCreated], "the events change");
    checks.equal(&updated.sealed_secret_previous, &Some(vec![9]), "the previous secret");
    checks.equal(&updated.secret_rotated_at, &Some(far_future()), "the rotation time");
    checks.precondition_failed(tx.webhooks().update(changed, created.version).await, "a stale version");
    checks.not_found(
        tx.webhooks().update(subscription_for(0x998, &[])?, 1).await,
        "an unknown subscription",
    );

    checks.equal(
        &tx.webhooks().record_failure(created.id).await?,
        &1,
        "the first failure",
    );
    checks.equal(
        &tx.webhooks().record_failure(created.id).await?,
        &2,
        "the second failure",
    );
    let counted = tx.webhooks().get(created.id).await?;
    checks.equal(&counted.failure_count, &2, "the failures are stored");
    checks.equal(&counted.version, &updated.version, "without a new version");
    tx.webhooks().record_success(created.id).await?;
    checks.equal(
        &tx.webhooks().get(created.id).await?.failure_count,
        &0,
        "a success resets the counter",
    );
    tx.webhooks().disable(created.id, "too many failures").await?;
    let disabled = tx.webhooks().get(created.id).await?;
    checks.that(!disabled.active, "a disabled subscription is inactive");
    checks.equal(
        &disabled.disabled_reason.as_deref(),
        &Some("too many failures"),
        "with the reason",
    );
    checks.equal(&disabled.version, &(updated.version + 1), "and a new version");
    checks.not_found(
        tx.webhooks().record_failure(id(0x999)).await,
        "a failure of an unknown subscription",
    );
    checks.not_found(
        tx.webhooks().record_success(id(0x999)).await,
        "a success of an unknown subscription",
    );
    checks.not_found(
        tx.webhooks().disable(id(0x999), "x").await,
        "disabling an unknown subscription",
    );

    let first = tx.webhooks().create_delivery(delivery_for(0xC01, created.id)).await?;
    tx.webhooks().create_delivery(delivery_for(0xC02, created.id)).await?;
    tx.webhooks().create_delivery(delivery_for(0xC03, inactive.id)).await?;
    checks.equal(&first.version, &1, "a new delivery has version 1");
    checks.equal(&tx.webhooks().get_delivery(first.id).await?, &first, "get a delivery");
    let page = tx.webhooks().list_deliveries(created.id, PageReq::first(1)).await?;
    checks.equal(
        &page.items.iter().map(|found| found.id).collect::<Vec<_>>(),
        &vec![first.id],
        "the first page of deliveries",
    );
    checks.that(page.next.is_some(), "has a cursor");
    checks.equal(
        &tx.webhooks()
            .list_deliveries(created.id, PageReq::default())
            .await?
            .items
            .len(),
        &2,
        "only the deliveries of the subscription",
    );
    checks.not_found(
        tx.webhooks().create_delivery(delivery_for(0xC04, id(0x999))).await,
        "a delivery of an unknown subscription",
    );
    checks.not_found(
        tx.webhooks().list_deliveries(id(0x999), PageReq::default()).await,
        "the deliveries of an unknown subscription",
    );
    let mut settled = first.clone();
    settled.status = DeliveryStatus::Delivered;
    settled.attempts = 1;
    settled.response_status = Some(204);
    settled.last_error = Some("none".to_owned());
    let settled_stored = tx.webhooks().update_delivery(settled.clone(), first.version).await?;
    checks.equal(&settled_stored.status, &DeliveryStatus::Delivered, "the status changes");
    checks.equal(
        &settled_stored.response_status,
        &Some(204),
        "the response status is stored",
    );
    checks.equal(&settled_stored.version, &2, "the version counts up");
    checks.precondition_failed(
        tx.webhooks().update_delivery(settled, first.version).await,
        "a stale version",
    );
    checks.not_found(
        tx.webhooks().update_delivery(delivery_for(0x998, created.id), 1).await,
        "an unknown delivery",
    );

    tx.webhooks().delete(created.id).await?;
    checks.not_found(tx.webhooks().get(created.id).await, "a deleted subscription");
    checks.not_found(tx.webhooks().get_delivery(first.id).await, "its deliveries go with it");
    checks.not_found(tx.webhooks().delete(created.id).await, "deleting twice");
    tx.commit().await?;
    Ok(())
}

/// An external account.
pub(super) fn account_for(
    n: u128,
    principal: PrincipalId,
    provider: &str,
    mirror: Option<CalendarId>,
) -> ExternalAccount {
    ExternalAccount {
        id: id::<ExternalAccountId>(n),
        tenant_id: nobody(),
        principal_id: principal,
        provider: provider.to_owned(),
        account_ref: format!("{provider}-account"),
        sealed_tokens: vec![5, 5, 5],
        mirror_calendar_id: mirror,
        sync_state: serde_json::json!({"cursor": "c1"}),
        status: ExternalAccountStatus::Active,
        last_error: None,
        created_at: epoch(),
        updated_at: epoch(),
        version: 99,
    }
}

/// An OAuth state.
pub(super) fn oauth_state_for(
    n: u128,
    principal: PrincipalId,
    hash: u8,
    expires: chrono::DateTime<chrono::Utc>,
) -> OAuthState {
    OAuthState {
        id: uuid(n),
        tenant_id: nobody(),
        principal_id: principal,
        provider: "google".to_owned(),
        state_hash: vec![hash; 4],
        pkce_verifier_sealed: vec![7, 7],
        expires_at: expires,
        used_at: None,
        created_at: epoch(),
    }
}

/// Provider accounts and OAuth states.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn external_accounts_and_oauth_states(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let created = tx
        .external_accounts()
        .create(account_for(0xD01, world.olivia, "google", Some(world.shared)))
        .await?;
    tx.external_accounts()
        .create(account_for(0xD02, world.mia, "microsoft", None))
        .await?;
    checks.equal(&created.version, &1, "a new account has version 1");
    checks.equal(&created.tenant_id, &world.a, "bound to the tenant of the transaction");
    checks.equal(
        &created.sync_state,
        &serde_json::json!({"cursor": "c1"}),
        "the sync state is stored as JSON",
    );
    checks.equal(
        &created.sealed_tokens,
        &vec![5, 5, 5],
        "the sealed tokens are stored as given",
    );
    checks.equal(&tx.external_accounts().get(created.id).await?, &created, "get");
    checks.not_found(
        tx.external_accounts()
            .create(account_for(0xD03, id(0x999), "google", None))
            .await,
        "an account of an unknown principal",
    );
    checks.not_found(
        tx.external_accounts()
            .create(account_for(0xD04, world.olivia, "google", Some(id(0x999))))
            .await,
        "an account that mirrors into an unknown calendar",
    );
    let by_principal = tx
        .external_accounts()
        .list(
            &ExternalAccountFilter {
                principal: Some(world.olivia),
                ..ExternalAccountFilter::default()
            },
            PageReq::default(),
        )
        .await?;
    checks.equal(&by_principal.items.len(), &1, "the principal filter");
    let by_provider = tx
        .external_accounts()
        .list(
            &ExternalAccountFilter {
                provider: Some("microsoft".to_owned()),
                ..ExternalAccountFilter::default()
            },
            PageReq::default(),
        )
        .await?;
    checks.equal(&by_provider.items.len(), &1, "the provider filter");
    let page = tx
        .external_accounts()
        .list(&ExternalAccountFilter::default(), PageReq::first(1))
        .await?;
    checks.that(page.items.len() == 1 && page.next.is_some(), "paging");
    let mut changed = created.clone();
    changed.status = ExternalAccountStatus::Error;
    changed.last_error = Some("revoked".to_owned());
    changed.sync_state = serde_json::json!({"cursor": "c2"});
    changed.sealed_tokens = vec![6];
    let updated = tx.external_accounts().update(changed.clone(), created.version).await?;
    checks.equal(&updated.version, &2, "an update bumps the version");
    checks.equal(&updated.status, &ExternalAccountStatus::Error, "the status changes");
    checks.equal(
        &updated.sync_state,
        &serde_json::json!({"cursor": "c2"}),
        "the sync state changes",
    );
    checks.equal(&updated.provider, &created.provider, "the provider does not");
    checks.precondition_failed(
        tx.external_accounts().update(changed, created.version).await,
        "a stale version",
    );
    checks.not_found(
        tx.external_accounts()
            .update(account_for(0x998, world.olivia, "google", None), 1)
            .await,
        "an unknown account",
    );

    let calendar = tx.calendars().get(world.shared).await?;
    tx.calendars().soft_delete(calendar.id, calendar.version).await?;
    tx.calendars().purge(calendar.id).await?;
    checks.equal(
        &tx.external_accounts().get(created.id).await?.mirror_calendar_id,
        &None,
        "purging the mirror calendar clears the reference",
    );
    tx.external_accounts().delete(created.id).await?;
    checks.not_found(tx.external_accounts().get(created.id).await, "a deleted account");
    checks.not_found(tx.external_accounts().delete(created.id).await, "deleting twice");

    let fresh = tx
        .oauth_states()
        .create(oauth_state_for(0xE01, world.olivia, 1, far_future()))
        .await?;
    checks.equal(
        &fresh.tenant_id,
        &world.a,
        "an OAuth state is bound to the tenant of the transaction",
    );
    checks.equal(&fresh.used_at, &None, "unused");
    checks.unique(
        tx.oauth_states()
            .create(oauth_state_for(0xE02, world.olivia, 1, far_future()))
            .await,
        UniqueKey::OAuthState,
        "a duplicate state hash",
    );
    checks.not_found(
        tx.oauth_states()
            .create(oauth_state_for(0xE03, id(0x999), 3, far_future()))
            .await,
        "a state of an unknown principal",
    );
    let consumed = tx.oauth_states().consume(&[1; 4]).await?;
    checks.equal(&consumed.id, &fresh.id, "consuming returns the state");
    checks.that(consumed.used_at.is_some(), "marked used");
    checks.not_found(tx.oauth_states().consume(&[1; 4]).await, "a state works once");
    tx.oauth_states()
        .create(oauth_state_for(0xE04, world.olivia, 4, long_ago()))
        .await?;
    checks.not_found(tx.oauth_states().consume(&[4; 4]).await, "an expired state");
    checks.not_found(tx.oauth_states().consume(&[9; 4]).await, "an unknown state");
    tx.commit().await?;
    Ok(())
}

/// Only an in-flight record can be settled: a dispatcher whose lease expired must not overwrite what the
/// dispatcher that reclaimed the record decided (the message would be sent twice). The unfenced settle covers the
/// records that are already settled; `outbox_fenced_settling` covers the ones that were reclaimed and are held.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn outbox_settling(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let key_of = |n: u128| OutboxKey {
        tenant: world.a,
        id: id(n),
    };
    let mut tx = begin(db, world.a).await?;
    for n in [0xC01, 0xC02, 0xC03] {
        tx.outbox().enqueue(NewOutbox::now(id(n), push())).await?;
    }
    tx.commit().await?;

    let mut sys = system(db).await?;
    checks.lease_lost(
        sys.outbox_claim().complete(key_of(0xC03)).await,
        "completing a record nobody claimed",
    );
    checks.lease_lost(
        sys.outbox_claim().fail(key_of(0xC03), OutboxFailure::dead("x")).await,
        "failing a record nobody claimed",
    );

    // Dispatcher A claims two records with a lease that is over at once and stalls; dispatcher B reclaims them.
    let stalled = sys.outbox_claim().claim(2, Duration::ZERO).await?;
    checks.equal(&stalled.len(), &2, "dispatcher A claims two records");
    let reclaimed = sys.outbox_claim().claim(2, Duration::from_secs(600)).await?;
    checks.equal(
        &reclaimed.iter().map(|record| record.attempts).collect::<Vec<_>>(),
        &vec![2, 2],
        "dispatcher B reclaims them (a second attempt each)",
    );
    sys.outbox_claim().complete(key_of(0xC01)).await?;
    sys.outbox_claim()
        .fail(key_of(0xC02), OutboxFailure::retry("by B", far_future()))
        .await?;

    checks.lease_lost(
        sys.outbox_claim()
            .fail(key_of(0xC01), OutboxFailure::dead("late"))
            .await,
        "A's late failure of a record that B completed",
    );
    checks.lease_lost(
        sys.outbox_claim().complete(key_of(0xC01)).await,
        "A's late completion of a record that is done already",
    );
    checks.lease_lost(
        sys.outbox_claim().complete(key_of(0xC02)).await,
        "A's late completion of a record that B sent back for a retry",
    );
    checks.not_found(
        sys.outbox_claim().complete(key_of(0x999)).await,
        "settling a record that does not exist is still NotFound",
    );
    sys.commit().await?;

    let mut tx = begin(db, world.a).await?;
    checks.equal(
        &tx.outbox().get(id(0xC01)).await?.status,
        &OutboxStatus::Done,
        "the record B completed stays done",
    );
    let retry = tx.outbox().get(id(0xC02)).await?;
    checks.equal(
        &(retry.status, retry.last_error.as_deref()),
        &(OutboxStatus::Pending, Some("by B")),
        "the record B sent back for a retry keeps B's outcome",
    );
    tx.outbox().enqueue(NewOutbox::now(id(0xC04), push())).await?;
    tx.commit().await?;

    // A handler that did not try anything (a mail held back by the rate limit) defers: the record is due later
    // and the claim is not an attempt, so a long hold never uses up the attempt budget.
    let mut sys = system(db).await?;
    let claimed = sys.outbox_claim().claim(10, Duration::from_secs(600)).await?;
    checks.equal(
        &claimed
            .iter()
            .map(|record| (record.id, record.attempts))
            .collect::<Vec<_>>(),
        &vec![(id(0xC03), 1), (id(0xC04), 1)],
        "the records nobody claimed yet are claimed (one attempt each)",
    );
    let Some(held_claim) = claimed
        .iter()
        .find(|record| record.id == id(0xC04))
        .and_then(OutboxRecord::claim)
    else {
        checks.fail("the claim of the record to defer is missing");
        return Ok(());
    };
    sys.outbox_claim()
        .defer_claimed(held_claim, far_future(), "held back")
        .await?;
    checks.equal(
        &sys.outbox_claim().claim(10, Duration::from_secs(600)).await?.len(),
        &0,
        "a deferred record is not due before its time",
    );
    checks.lease_lost(
        sys.outbox_claim()
            .defer_claimed(held_claim, far_future(), "again")
            .await,
        "deferring a claim that was given back already",
    );
    checks.lease_lost(
        sys.outbox_claim()
            .defer_claimed(
                OutboxClaim {
                    key: key_of(0xC01),
                    ..held_claim
                },
                far_future(),
                "late",
            )
            .await,
        "deferring a record that is done",
    );
    checks.not_found(
        sys.outbox_claim()
            .defer_claimed(
                OutboxClaim {
                    key: key_of(0x999),
                    ..held_claim
                },
                far_future(),
                "x",
            )
            .await,
        "deferring a record that does not exist",
    );
    sys.commit().await?;
    let mut tx = begin(db, world.a).await?;
    let held = tx.outbox().get(id(0xC04)).await?;
    checks.equal(
        &(held.status, held.attempts, held.next_attempt_at, held.locked_until),
        &(OutboxStatus::Pending, 0, far_future(), None),
        "a deferred record is pending again, due later, without a lease and with its attempt given back",
    );
    checks.equal(&held.last_error.as_deref(), &Some("held back"), "and says why");
    Ok(())
}

/// The failure counter belongs to the dispatcher (an update from a stale copy does not erase it, re-enabling resets
/// it), and an event is delivered to a subscription once however often the fan-out repeats.
pub(super) async fn webhook_counters_and_duplicate_deliveries(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let created = tx
        .webhooks()
        .create(subscription_for(0xB11, &[EventType::PrincipalCreated])?)
        .await?;

    // An administrator reads the subscription, the dispatcher records failures, the administrator saves.
    let stale = tx.webhooks().get(created.id).await?;
    tx.webhooks().record_failure(created.id).await?;
    tx.webhooks().record_failure(created.id).await?;
    let mut edited = stale.clone();
    edited.description = Some("renamed".to_owned());
    let saved = tx.webhooks().update(edited, stale.version).await?;
    checks.equal(&saved.description.as_deref(), &Some("renamed"), "the edit is stored");
    checks.equal(
        &saved.failure_count,
        &2,
        "the failures recorded in between are not lost to the stale copy",
    );
    let mut forged = saved.clone();
    forged.failure_count = 0;
    checks.equal(
        &tx.webhooks().update(forged, saved.version).await?.failure_count,
        &2,
        "an update never writes the counter of the entity it is given",
    );

    // Re-enabling starts the count again.
    tx.webhooks().disable(created.id, "too many failures").await?;
    let disabled = tx.webhooks().get(created.id).await?;
    checks.equal(&disabled.failure_count, &2, "disabling keeps the count");
    let mut enabled = disabled.clone();
    enabled.active = true;
    enabled.disabled_reason = None;
    let again = tx.webhooks().update(enabled, disabled.version).await?;
    checks.that(
        again.active && again.disabled_reason.is_none(),
        "the subscription is active again",
    );
    checks.equal(&again.failure_count, &0, "and counts from zero");

    // One delivery per event and subscription.
    let first = tx.webhooks().create_delivery(delivery_for(0xB21, created.id)).await?;
    let mut repeat = delivery_for(0xB22, created.id);
    repeat.event_id = first.event_id;
    let found = tx.webhooks().create_delivery(repeat).await?;
    checks.equal(&found, &first, "a repeated fan-out finds the delivery it made before");
    checks.equal(
        &tx.webhooks()
            .list_deliveries(created.id, PageReq::default())
            .await?
            .items
            .len(),
        &1,
        "and creates no second record",
    );
    tx.webhooks().create_delivery(delivery_for(0xB23, created.id)).await?;
    checks.equal(
        &tx.webhooks()
            .list_deliveries(created.id, PageReq::default())
            .await?
            .items
            .len(),
        &2,
        "another event is another delivery",
    );
    tx.commit().await?;
    Ok(())
}

/// A dispatcher whose lease ran out cannot settle a record that another dispatcher has reclaimed and still holds:
/// the fenced settle methods only act for the claim that is current. (The unfenced `complete` and `fail` cannot tell
/// the two holders apart, see `outbox_settling`.)
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
pub(super) async fn outbox_fenced_settling(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let key_of = |n: u128| OutboxKey {
        tenant: world.a,
        id: id(n),
    };
    let mut tx = begin(db, world.a).await?;
    for n in [0xC41, 0xC42, 0xC43] {
        tx.outbox().enqueue(NewOutbox::now(id(n), push())).await?;
    }
    tx.commit().await?;

    let mut sys = system(db).await?;
    // Dispatcher A claims two records with a lease that is over at once and stalls; dispatcher B reclaims them.
    let stalled = sys.outbox_claim().claim(2, Duration::ZERO).await?;
    let reclaimed = sys.outbox_claim().claim(2, Duration::from_secs(600)).await?;
    let claims_of = |records: &[OutboxRecord]| {
        records
            .iter()
            .filter_map(OutboxRecord::claim)
            .collect::<Vec<OutboxClaim>>()
    };
    let (a, b) = (claims_of(&stalled), claims_of(&reclaimed));
    checks.equal(
        &(a.len(), b.len()),
        &(2, 2),
        "both dispatchers hold claims of two records",
    );
    checks.equal(
        &a.iter().map(|claim| claim.key).collect::<Vec<_>>(),
        &b.iter().map(|claim| claim.key).collect::<Vec<_>>(),
        "on the same two records",
    );
    checks.differ(
        &a,
        &b,
        "a reclaim is a new claim (another attempt number and lease end)",
    );
    let (Some(a0), Some(a1), Some(b0), Some(b1)) = (a.first(), a.get(1), b.first(), b.get(1)) else {
        checks.fail("the claims are missing");
        return Ok(());
    };

    // A comes back to life and tries to settle what B holds: refused, nothing changes.
    checks.lease_lost(
        sys.outbox_claim().complete_claimed(*a0).await,
        "A's late completion of a record that B holds",
    );
    checks.lease_lost(
        sys.outbox_claim()
            .defer_claimed(*a0, far_future(), "A's late hold")
            .await,
        "A's late deferral of a record that B holds",
    );
    checks.lease_lost(
        sys.outbox_claim().fail_claimed(*a1, OutboxFailure::dead("late")).await,
        "A's late failure of a record that B holds",
    );
    checks.equal(
        &sys.outbox_claim().release_claimed(&a).await?,
        &0,
        "A's stale claims release nothing (a graceful shutdown of A leaves B's leases alone)",
    );
    checks.equal(
        &sys.outbox_claim().stats().await?.in_flight,
        &2,
        "both records are still in flight, held by B",
    );

    // B settles with its own claims.
    sys.outbox_claim().complete_claimed(*b0).await?;
    sys.outbox_claim()
        .fail_claimed(*b1, OutboxFailure::retry("by B", far_future()))
        .await?;
    checks.lease_lost(
        sys.outbox_claim().complete_claimed(*b0).await,
        "settling twice with the same claim",
    );
    checks.not_found(
        sys.outbox_claim()
            .complete_claimed(OutboxClaim {
                key: key_of(0x999),
                ..*b0
            })
            .await,
        "a claim of a record that does not exist",
    );

    // The record nobody claimed yet: a fresh claim can be released with its own claim and is due again at once.
    let third = sys.outbox_claim().claim(1, Duration::from_secs(600)).await?;
    let held = claims_of(&third);
    checks.equal(&held.len(), &1, "the third record is claimed");
    checks.equal(
        &sys.outbox_claim().release_claimed(&held).await?,
        &1,
        "a claim releases its own lease",
    );
    sys.commit().await?;

    let mut tx = begin(db, world.a).await?;
    checks.equal(
        &tx.outbox().get(id(0xC41)).await?.status,
        &OutboxStatus::Done,
        "B's completion stands",
    );
    let retry = tx.outbox().get(id(0xC42)).await?;
    checks.equal(
        &(retry.status, retry.last_error.as_deref()),
        &(OutboxStatus::Pending, Some("by B")),
        "B's failure stands",
    );
    let released = tx.outbox().get(id(0xC43)).await?;
    checks.equal(
        &(released.status, released.attempts),
        &(OutboxStatus::Pending, 0),
        "a released lease is pending again and the attempt that never finished is not counted",
    );
    Ok(())
}
