//! Cases of tenant isolation (`ENGINEERING_RULES` R4): every repository method, called in a transaction of
//! another tenant with the ids of the first, finds nothing and changes nothing.
//!
//! The first tenant gets one row of every kind; the second tenant's transaction then calls every method of every
//! repository with those ids. Reads answer `NotFound`, `None` or an empty list; writes answer `NotFound`; and a
//! last look at the first tenant shows that nothing changed.

use davhaven_domain::{
    BindingId, CalendarKind, CalendarUserAddress, CollectionKey, CollectionKind, CredentialId, CredentialKind,
    CredentialRef, EventType, ExternalAccountId, GrantId, GrantStatus, InboxItemId, NotificationId, ObjectId,
    ObjectUri, OutboxId, PrincipalKind, SearchCriterion, SearchField, TextMatch, TokenId, TokenKind, Uid, WebhookId,
};
use davhaven_ports::store::ApiTokenFilter;
use davhaven_ports::{
    AuditFilter, CalendarFilter, CollectionProperty, CredentialUse, Expected, ExternalAccountFilter, IdempotencyClaim,
    IdempotencyRecord, IdempotencyStatus, InboxScope, IndexFilter, LeasedClaim, NewOutbox, OutboxFilter, OutboxMessage,
    PageReq, PrincipalFilter, PrincipalQuery, PropertyScope, Rehash, Reserved, StoredHash,
};
use std::time::Duration;

use super::Outcome;
use super::world::{
    Db, StoreChecks, World, address, api_token, app_password, begin, binding, calendar, far_future, feed_token, grant,
    id, inbox_item, key, notification, principal, rsvp_token, scheduling, seed, uuid, version,
};
use crate::suite::Checks;
use davhaven_domain::{AuditActor, AuditEvent};
use davhaven_ports::NewAudit;

/// The ids of the rows the first tenant owns.
struct Populated {
    world: World,
    binding: BindingId,
    grant: GrantId,
    object: ObjectId,
    object_uri: ObjectUri,
    object_uid: Uid,
    rsvp: TokenId,
    notification: NotificationId,
    notification_uri: ObjectUri,
    inbox: InboxItemId,
    inbox_uri: ObjectUri,
    app_password: CredentialId,
    api_token: TokenId,
    feed: TokenId,
    webhook: WebhookId,
    delivery: davhaven_domain::DeliveryId,
    account: ExternalAccountId,
    outbox: OutboxId,
    attendee: CalendarUserAddress,
}

/// Seeds the world and gives the first tenant a row of every kind.
#[expect(clippy::too_many_lines, reason = "seeds one row of everything")]
async fn populate(db: &Db) -> Result<Populated, davhaven_ports::StoreError> {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let mut olivia = tx.principals().get(world.olivia).await?;
    olivia.external_ref = Some("ext-olivia".to_owned());
    tx.principals().update(olivia.clone(), olivia.version).await?;
    tx.principals()
        .set_addresses(
            world.olivia,
            vec![address(world.olivia, "mailto:olivia@example.org", true)?],
        )
        .await?;
    let bound = tx
        .bindings()
        .create(binding(0x501, world.olivia, world.personal, "personal")?)
        .await?;
    tx.properties()
        .set(CollectionProperty {
            calendar_id: world.personal,
            scope: PropertyScope::Shared,
            ns: "DAV:".to_owned(),
            name: "displayname".to_owned(),
            value_xml: "<displayname/>".to_owned(),
        })
        .await?;
    let mut invited = grant(0x601, world.shared, world.mia, GrantStatus::Accepted);
    invited.invite_uid = Some(key(Uid::parse("inv-1"))?);
    let granted = tx.grants().create(invited).await?;
    let meeting = scheduling(
        version(0x401, "o.ics", "u-o")?,
        "mailto:olivia@example.org",
        &[("mailto:mia@example.org", Some(world.mia))],
    )?;
    let meeting = super::world::keyed(meeting, "k:1")?;
    let object_uri = meeting.uri.clone();
    let object_uid = meeting.index.uid.clone();
    let written = tx.objects().put(world.personal, meeting, Expected::Absent).await?;
    let token = tx
        .rsvp()
        .create(rsvp_token(
            0x731,
            written.object_id,
            "mailto:mia@example.org",
            "rsvp-a",
        )?)
        .await?;
    let note = tx
        .notifications()
        .create(notification(0x801, world.mia, "n1.xml", "invite-1")?)
        .await?;
    let item = tx
        .inbox()
        .create(inbox_item(0x901, world.mia, "i1.ics", false)?)
        .await?;
    let password = tx
        .credentials()
        .create_app_password(app_password(0x701, world.mia, "mia-pass"))
        .await?;
    let api = tx
        .credentials()
        .create_api_token(api_token(0x710, TokenKind::Tenant, None, "tenanttoken1"))
        .await?;
    let feed = tx
        .credentials()
        .create_feed_token(feed_token(0x721, world.mia, vec![world.personal], "feedtoken001"))
        .await?;
    let hook = tx
        .webhooks()
        .create(super::delivery::subscription_for(
            0xB01,
            &[EventType::PrincipalCreated],
        )?)
        .await?;
    let delivered = tx
        .webhooks()
        .create_delivery(super::delivery::delivery_for(0xC01, hook.id))
        .await?;
    let account = tx
        .external_accounts()
        .create(super::delivery::account_for(
            0xD01,
            world.olivia,
            "google",
            Some(world.shared),
        ))
        .await?;
    tx.oauth_states()
        .create(super::delivery::oauth_state_for(0xE01, world.olivia, 1, far_future()))
        .await?;
    tx.outbox()
        .enqueue(NewOutbox::now(id(0xA01), OutboxMessage::ProviderPush(Reserved {})))
        .await?;
    tx.idempotency().claim(request(id(0x710), "key-1")).await?;
    tx.audit()
        .append(NewAudit {
            id: uuid(1),
            actor: AuditActor::system(),
            event: AuditEvent::TenantCreated,
        })
        .await?;
    tx.commit().await?;
    Ok(Populated {
        world,
        binding: bound.id,
        grant: granted.id,
        object: written.object_id,
        object_uri,
        object_uid,
        rsvp: token.id,
        notification: note.id,
        notification_uri: note.uri,
        inbox: item.id,
        inbox_uri: item.uri,
        app_password: password.id,
        api_token: api.id,
        feed: feed.id,
        webhook: hook.id,
        delivery: delivered.id,
        account: account.id,
        outbox: id(0xA01),
        attendee: key(CalendarUserAddress::parse("mailto:mia@example.org"))?,
    })
}

/// An idempotency request.
fn request(token: TokenId, name: &str) -> IdempotencyRecord {
    IdempotencyRecord {
        token_id: token,
        key: name.to_owned(),
        method: "POST".to_owned(),
        path: "/x".to_owned(),
        fingerprint: "f".to_owned(),
        status: IdempotencyStatus::InFlight,
        response_status: None,
        response: None,
        expires_at: far_future(),
    }
}

/// The change-log key of each kind for the principal or calendar.
fn logs(populated: &Populated) -> [CollectionKey; 4] {
    let world = populated.world;
    [
        CollectionKey {
            kind: CollectionKind::Calendar,
            id: world.personal.as_uuid(),
        },
        CollectionKey {
            kind: CollectionKind::Home,
            id: world.olivia.as_uuid(),
        },
        CollectionKey {
            kind: CollectionKind::Inbox,
            id: world.mia.as_uuid(),
        },
        CollectionKey {
            kind: CollectionKind::Notifications,
            id: world.mia.as_uuid(),
        },
    ]
}

/// Reads with the ids of another tenant find nothing.
pub(super) async fn foreign_tenant_reads(db: &Db, checks: &mut Checks) -> Outcome {
    let populated = populate(db).await?;
    reads(db, &populated, checks).await
}

/// The calls of [`foreign_tenant_reads`] on a populated database.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
async fn reads(db: &Db, populated: &Populated, checks: &mut Checks) -> Outcome {
    let world = populated.world;
    let mut tx = begin(db, world.b).await?;

    checks.equal(
        &tx.tenant().get().await?.slug.as_str(),
        &"globex",
        "a tenant transaction reads its own tenant row",
    );
    checks.not_found(tx.principals().get(world.olivia).await, "principals.get");
    checks.not_found(
        tx.principals()
            .get_by_name(&key(davhaven_domain::PrincipalName::parse("olivia"))?)
            .await,
        "principals.get_by_name",
    );
    checks.equal(
        &tx.principals().find_by_external_ref("ext-olivia").await?,
        &None,
        "principals.find_by_external_ref",
    );
    checks.equal(
        &tx.principals()
            .find_by_address(&key(CalendarUserAddress::parse("mailto:olivia@example.org"))?)
            .await?,
        &None,
        "principals.find_by_address",
    );
    checks.equal(
        &tx.principals()
            .list(&PrincipalFilter::default(), PageReq::default())
            .await?
            .items
            .len(),
        &1,
        "principals.list sees only its own principal",
    );
    let hits = tx
        .principals()
        .search(&PrincipalQuery {
            text: "olivia".to_owned(),
            kinds: Vec::new(),
            limit: 10,
            ..PrincipalQuery::default()
        })
        .await?;
    checks.equal(&hits.len(), &0, "principals.search");
    // The kinds and the criteria narrow a search; they never widen it beyond the tenant of the transaction.
    for (kinds, any_of) in [
        (vec![PrincipalKind::User], false),
        (vec![PrincipalKind::User, PrincipalKind::Group], true),
    ] {
        let hits = tx
            .principals()
            .search(&PrincipalQuery {
                kinds,
                limit: 10,
                criteria: vec![
                    SearchCriterion::contains("olivia"),
                    SearchCriterion::new("olivia", vec![SearchField::Name], TextMatch::Equals),
                ],
                any_of,
                ..PrincipalQuery::default()
            })
            .await?;
        checks.equal(&hits.len(), &0, "principals.search with kinds and criteria");
    }
    checks.not_found(tx.principals().addresses(world.olivia).await, "principals.addresses");
    checks.not_found(tx.memberships().members(world.team).await, "memberships.members");
    checks.equal(
        &tx.memberships().groups_of(world.mia).await?,
        &Vec::new(),
        "memberships.groups_of",
    );
    checks.equal(
        &tx.principals()
            .find_by_addresses(&[key(CalendarUserAddress::parse("mailto:olivia@example.org"))?])
            .await?,
        &Vec::new(),
        "principals.find_by_addresses",
    );
    checks.equal(
        &tx.principals()
            .get_many(&[world.olivia, world.mia, world.team])
            .await?
            .len(),
        &0,
        "principals.get_many",
    );
    checks.equal(
        &tx.principals()
            .get_many_by_name(&[key(davhaven_domain::PrincipalName::parse("olivia"))?])
            .await?
            .len(),
        &0,
        "principals.get_many_by_name",
    );
    checks.equal(
        &tx.principals().addresses_many(&[world.olivia]).await?,
        &Vec::new(),
        "principals.addresses_many",
    );
    checks.equal(
        &tx.memberships().members_of_many(&[world.team]).await?,
        &Vec::new(),
        "memberships.members_of_many",
    );
    checks.equal(
        &tx.memberships().groups_of_many(&[world.mia]).await?,
        &Vec::new(),
        "memberships.groups_of_many",
    );

    checks.not_found(tx.calendars().get(world.personal).await, "calendars.get");
    checks.equal(
        &tx.calendars().get_many(&[world.personal, world.shared]).await?.len(),
        &0,
        "calendars.get_many",
    );
    checks.not_found(
        tx.calendars()
            .get_by_slug(world.olivia, &key(davhaven_domain::CalendarSlug::parse("personal"))?)
            .await,
        "calendars.get_by_slug",
    );
    checks.equal(
        &tx.calendars().list_owned(world.olivia).await?.len(),
        &0,
        "calendars.list_owned",
    );
    checks.equal(
        &tx.calendars()
            .list(&CalendarFilter::default(), PageReq::default())
            .await?
            .items
            .len(),
        &0,
        "calendars.list",
    );
    checks.equal(
        &tx.calendars().visible_without_binding(world.mia).await?.len(),
        &0,
        "calendars.visible_without_binding",
    );
    checks.not_found(
        tx.calendars().access_facts(world.personal, None).await,
        "calendars.access_facts",
    );
    checks.equal(
        &tx.calendars()
            .access_facts_many(&[world.personal, world.shared], Some(world.olivia))
            .await?
            .len(),
        &0,
        "calendars.access_facts_many",
    );
    checks.not_found(tx.calendars().lock(&[world.personal]).await, "calendars.lock");

    checks.not_found(tx.bindings().get(populated.binding).await, "bindings.get");
    checks.not_found(
        tx.bindings()
            .get_by_slug(world.olivia, &key(davhaven_domain::CalendarSlug::parse("personal"))?)
            .await,
        "bindings.get_by_slug",
    );
    checks.equal(
        &tx.bindings().find_for_calendar(world.olivia, world.personal).await?,
        &None,
        "bindings.find_for_calendar",
    );
    checks.equal(
        &tx.bindings().list_for(world.olivia).await?.len(),
        &0,
        "bindings.list_for",
    );
    checks.not_found(
        tx.bindings().list_for_calendar(world.personal).await,
        "bindings.list_for_calendar",
    );
    checks.equal(
        &tx.bindings()
            .find_for_calendars(&[(world.olivia, world.personal)])
            .await?
            .len(),
        &0,
        "bindings.find_for_calendars",
    );

    checks.not_found(
        tx.properties().list(world.personal, PropertyScope::Shared).await,
        "properties.list",
    );
    checks.not_found(
        tx.properties()
            .get(world.personal, PropertyScope::Shared, "DAV:", "displayname")
            .await,
        "properties.get",
    );
    checks.not_found(
        tx.properties().count(world.personal, PropertyScope::Shared).await,
        "properties.count",
    );
    checks.equal(
        &tx.properties()
            .list_many(&[(world.personal, populated.binding)])
            .await?
            .len(),
        &0,
        "properties.list_many",
    );

    checks.not_found(tx.grants().get(populated.grant).await, "grants.get");
    checks.equal(&tx.grants().find(world.shared, world.mia).await?, &None, "grants.find");
    checks.equal(
        &tx.grants().find_by_invite_uid(&key(Uid::parse("inv-1"))?).await?,
        &None,
        "grants.find_by_invite_uid",
    );
    checks.not_found(tx.grants().for_calendar(world.shared).await, "grants.for_calendar");
    checks.equal(
        &tx.grants().for_calendars(&[world.shared, world.personal]).await?.len(),
        &0,
        "grants.for_calendars",
    );
    checks.equal(
        &tx.grants().for_grantee(world.mia).await?.len(),
        &0,
        "grants.for_grantee",
    );

    checks.not_found(
        tx.objects().get(world.personal, &populated.object_uri).await,
        "objects.get",
    );
    checks.not_found(tx.objects().get_by_id(populated.object).await, "objects.get_by_id");
    checks.not_found(
        tx.objects().get_by_uid(world.personal, &populated.object_uid).await,
        "objects.get_by_uid",
    );
    checks.not_found(
        tx.objects()
            .get_by_external_key(world.personal, &key(davhaven_domain::ExternalKey::parse("k:1"))?)
            .await,
        "objects.get_by_external_key",
    );
    checks.equal(
        &tx.objects()
            .find_scheduling_uid(world.olivia, &populated.object_uid)
            .await?,
        &None,
        "objects.find_scheduling_uid",
    );
    checks.not_found(
        tx.objects()
            .query(world.personal, &IndexFilter::all(), PageReq::default())
            .await,
        "objects.query",
    );
    checks.not_found(
        tx.objects().list(world.personal, PageReq::default()).await,
        "objects.list",
    );
    checks.not_found(
        tx.objects().list_index(world.personal, PageReq::default()).await,
        "objects.list_index",
    );
    checks.not_found(
        tx.objects()
            .query_index(world.personal, &IndexFilter::all(), PageReq::default())
            .await,
        "objects.query_index",
    );
    checks.not_found(
        tx.objects().uri_for_uid(world.personal, &populated.object_uid).await,
        "objects.uri_for_uid",
    );
    checks.equal(
        &tx.objects()
            .uri_for_scheduling_uid(world.olivia, &populated.object_uid)
            .await?,
        &None,
        "objects.uri_for_scheduling_uid",
    );
    checks.not_found(tx.objects().attendees(populated.object).await, "objects.attendees");

    for log in logs(populated) {
        checks.not_found(tx.changes().state(log).await, "changes.state");
        checks.not_found(tx.changes().since(log, uuid(0x1), 0, 10).await, "changes.since");
    }

    checks.not_found(
        tx.notifications().get(populated.notification).await,
        "notifications.get",
    );
    checks.not_found(
        tx.notifications()
            .get_by_uri(world.mia, &populated.notification_uri)
            .await,
        "notifications.get_by_uri",
    );
    checks.equal(
        &tx.notifications()
            .get_many_by_uri(world.mia, std::slice::from_ref(&populated.notification_uri))
            .await?
            .len(),
        &0,
        "notifications.get_many_by_uri",
    );
    checks.equal(
        &tx.notifications()
            .find_by_uid(world.mia, &key(Uid::parse("invite-1"))?)
            .await?,
        &None,
        "notifications.find_by_uid",
    );
    checks.equal(
        &tx.notifications().list(world.mia).await?.len(),
        &0,
        "notifications.list",
    );
    checks.equal(
        &tx.inbox()
            .get_many_by_uri(world.mia, std::slice::from_ref(&populated.inbox_uri))
            .await?
            .len(),
        &0,
        "inbox.get_many_by_uri",
    );
    checks.not_found(tx.inbox().get(populated.inbox).await, "inbox.get");
    checks.not_found(
        tx.inbox().get_by_uri(world.mia, &populated.inbox_uri).await,
        "inbox.get_by_uri",
    );
    checks.equal(
        &tx.inbox().list(world.mia, InboxScope::Delivered).await?.len(),
        &0,
        "inbox.list",
    );

    checks.not_found(
        tx.credentials().get_app_password(populated.app_password).await,
        "credentials.get_app_password",
    );
    checks.equal(
        &tx.credentials().list_app_passwords(world.mia).await?.len(),
        &0,
        "credentials.list_app_passwords",
    );
    checks.not_found(
        tx.credentials().get_api_token(populated.api_token).await,
        "credentials.get_api_token",
    );
    checks.equal(
        &tx.credentials()
            .list_api_tokens(&ApiTokenFilter::default(), PageReq::default())
            .await?
            .items
            .len(),
        &0,
        "credentials.list_api_tokens",
    );
    checks.not_found(
        tx.credentials().get_feed_token(populated.feed).await,
        "credentials.get_feed_token",
    );
    checks.equal(
        &tx.credentials().list_feed_tokens(world.mia).await?.len(),
        &0,
        "credentials.list_feed_tokens",
    );
    checks.not_found(tx.rsvp().get(populated.rsvp).await, "rsvp.get");
    checks.equal(
        &tx.rsvp().for_object(populated.object).await?.len(),
        &0,
        "rsvp.for_object",
    );
    checks.equal(
        &tx.rsvp().find_live(populated.object, &populated.attendee).await?,
        &None,
        "rsvp.find_live",
    );

    checks.not_found(tx.outbox().get(populated.outbox).await, "outbox.get");
    checks.equal(
        &tx.outbox()
            .list(&OutboxFilter::default(), PageReq::default())
            .await?
            .items
            .len(),
        &0,
        "outbox.list",
    );
    checks.not_found(tx.webhooks().get(populated.webhook).await, "webhooks.get");
    checks.equal(
        &tx.webhooks().list(PageReq::default()).await?.items.len(),
        &0,
        "webhooks.list",
    );
    checks.equal(
        &tx.webhooks().subscribed_to(EventType::PrincipalCreated).await?.len(),
        &0,
        "webhooks.subscribed_to",
    );
    checks.not_found(
        tx.webhooks().get_delivery(populated.delivery).await,
        "webhooks.get_delivery",
    );
    checks.not_found(
        tx.webhooks()
            .list_deliveries(populated.webhook, PageReq::default())
            .await,
        "webhooks.list_deliveries",
    );
    checks.not_found(
        tx.external_accounts().get(populated.account).await,
        "external_accounts.get",
    );
    checks.equal(
        &tx.external_accounts()
            .list(&ExternalAccountFilter::default(), PageReq::default())
            .await?
            .items
            .len(),
        &0,
        "external_accounts.list",
    );
    checks.not_found(tx.oauth_states().consume(&[1; 4]).await, "oauth_states.consume");
    checks.equal(
        &tx.audit()
            .list(&AuditFilter::default(), PageReq::default())
            .await?
            .items
            .len(),
        &0,
        "audit.list",
    );
    checks.equal(
        &tx.idempotency().claim(request(id(0x710), "key-1")).await?,
        &IdempotencyClaim::Claimed,
        "idempotency keys of another tenant do not collide",
    );
    checks.that(
        matches!(
            tx.idempotency()
                .claim_leased(request(id(0x710), "key-2"), Duration::from_secs(60))
                .await?,
            LeasedClaim::Claimed { .. }
        ),
        "idempotency.claim_leased (a free key in this tenant, whatever the first tenant holds)",
    );
    Ok(())
}

/// Writes with the ids of another tenant fail and leave the first tenant's rows alone.
pub(super) async fn foreign_tenant_writes(db: &Db, checks: &mut Checks) -> Outcome {
    let populated = populate(db).await?;
    writes(db, &populated, checks).await
}

/// The calls of [`foreign_tenant_writes`] on a populated database.
#[expect(clippy::too_many_lines, reason = "a contract case is one linear script of checks")]
async fn writes(db: &Db, populated: &Populated, checks: &mut Checks) -> Outcome {
    let world = populated.world;
    let mut tx = begin(db, world.b).await?;

    let olivia = principal(0x101, "olivia", PrincipalKind::User)?;
    checks.not_found(tx.principals().update(olivia.clone(), 2).await, "principals.update");
    checks.not_found(
        tx.principals().bump_credential_generation(world.olivia).await,
        "principals.bump_credential_generation",
    );
    checks.not_found(
        tx.principals()
            .set_addresses(
                world.olivia,
                vec![address(world.olivia, "mailto:x@example.org", false)?],
            )
            .await,
        "principals.set_addresses",
    );
    checks.not_found(tx.principals().purge(world.olivia).await, "principals.purge");
    checks.not_found(
        tx.memberships().set_members(world.team, &[]).await,
        "memberships.set_members",
    );
    checks.not_found(
        tx.memberships().add_member(world.team, world.mia).await,
        "memberships.add_member",
    );
    checks.not_found(
        tx.memberships().remove_member(world.team, world.mia).await,
        "memberships.remove_member",
    );

    checks.not_found(
        tx.calendars()
            .create(calendar(0x370, world.olivia, "intruder", CalendarKind::User)?)
            .await,
        "calendars.create for a foreign owner",
    );
    checks.not_found(
        tx.calendars()
            .update(calendar(0x301, world.olivia, "personal", CalendarKind::Personal)?, 1)
            .await,
        "calendars.update",
    );
    checks.not_found(
        tx.calendars().soft_delete(world.personal, 1).await,
        "calendars.soft_delete",
    );
    checks.not_found(tx.calendars().touch(world.personal).await, "calendars.touch");
    checks.not_found(tx.calendars().purge(world.personal).await, "calendars.purge");
    checks.not_found(
        tx.bindings()
            .create(binding(0x580, world.olivia, world.personal, "x")?)
            .await,
        "bindings.create",
    );
    checks.not_found(
        tx.bindings()
            .update(binding(0x501, world.olivia, world.personal, "personal")?, 1)
            .await,
        "bindings.update",
    );
    checks.not_found(tx.bindings().delete(populated.binding).await, "bindings.delete");
    checks.not_found(
        tx.properties()
            .set(CollectionProperty {
                calendar_id: world.personal,
                scope: PropertyScope::Shared,
                ns: "DAV:".to_owned(),
                name: "x".to_owned(),
                value_xml: "<x/>".to_owned(),
            })
            .await,
        "properties.set",
    );
    checks.not_found(
        tx.properties()
            .remove(world.personal, PropertyScope::Shared, "DAV:", "displayname")
            .await,
        "properties.remove",
    );
    checks.not_found(
        tx.grants()
            .create(grant(0x680, world.shared, world.mia, GrantStatus::Accepted))
            .await,
        "grants.create",
    );
    checks.not_found(
        tx.grants()
            .update(grant(0x601, world.shared, world.mia, GrantStatus::Declined), 1)
            .await,
        "grants.update",
    );
    checks.not_found(tx.grants().delete(populated.grant).await, "grants.delete");

    let event = version(0x4F0, "foreign.ics", "foreign")?;
    checks.not_found(
        tx.objects().put(world.personal, event, Expected::Any).await,
        "objects.put",
    );
    checks.not_found(
        tx.objects()
            .delete(world.personal, &populated.object_uri, Expected::Any)
            .await,
        "objects.delete",
    );
    checks.not_found(
        tx.objects()
            .move_to(
                world.personal,
                &populated.object_uri,
                world.shared,
                &populated.object_uri,
            )
            .await,
        "objects.move_to",
    );
    checks.not_found(tx.changes().touch_home(world.olivia).await, "changes.touch_home");
    checks.not_found(tx.changes().touch_inbox(world.mia).await, "changes.touch_inbox");
    checks.not_found(
        tx.changes().touch_notifications(world.mia).await,
        "changes.touch_notifications",
    );

    checks.not_found(
        tx.notifications()
            .create(notification(0x880, world.mia, "x.xml", "x")?)
            .await,
        "notifications.create",
    );
    checks.not_found(
        tx.notifications()
            .update(notification(0x801, world.mia, "n1.xml", "invite-1")?, 1)
            .await,
        "notifications.update",
    );
    checks.not_found(
        tx.notifications().delete(populated.notification).await,
        "notifications.delete",
    );
    checks.not_found(
        tx.inbox().create(inbox_item(0x980, world.mia, "x.ics", false)?).await,
        "inbox.create",
    );
    checks.not_found(tx.inbox().delete(populated.inbox).await, "inbox.delete");

    checks.not_found(
        tx.credentials()
            .create_app_password(app_password(0x780, world.mia, "intruder-1"))
            .await,
        "credentials.create_app_password",
    );
    checks.not_found(
        tx.credentials().revoke_app_password(populated.app_password).await,
        "credentials.revoke_app_password",
    );
    checks.not_found(
        tx.credentials()
            .create_api_token(api_token(0x781, TokenKind::Principal, Some(world.mia), "intruder-2"))
            .await,
        "credentials.create_api_token",
    );
    checks.not_found(
        tx.credentials().revoke_api_token(populated.api_token).await,
        "credentials.revoke_api_token",
    );
    checks.not_found(
        tx.credentials()
            .create_feed_token(feed_token(0x782, world.mia, vec![world.personal], "intruder-3"))
            .await,
        "credentials.create_feed_token",
    );
    checks.not_found(
        tx.credentials().revoke_feed_token(populated.feed).await,
        "credentials.revoke_feed_token",
    );
    checks.equal(
        &tx.credentials().revoke_all_for_principal(world.mia).await?,
        &0,
        "credentials.revoke_all_for_principal",
    );
    let uses = [CredentialUse {
        kind: CredentialKind::AppPassword,
        id: populated.app_password.as_uuid(),
        at: far_future(),
    }];
    checks.equal(
        &tx.credentials().touch_last_used(&uses).await?,
        &0,
        "credentials.touch_last_used",
    );
    checks.equal(
        &tx.credentials()
            .rehash(&Rehash {
                credential: CredentialRef {
                    kind: CredentialKind::AppPassword,
                    id: populated.app_password.as_uuid(),
                },
                from_kid: "k1".to_owned(),
                to: StoredHash::new(CredentialKind::AppPassword, "k2", vec![9; 4]),
            })
            .await?,
        &false,
        "credentials.rehash",
    );
    checks.not_found(
        tx.rsvp()
            .create(rsvp_token(
                0x783,
                populated.object,
                "mailto:mia@example.org",
                "intruder-4",
            )?)
            .await,
        "rsvp.create",
    );
    checks.not_found(tx.rsvp().record_use(populated.rsvp, None).await, "rsvp.record_use");
    checks.not_found(tx.rsvp().revoke(populated.rsvp).await, "rsvp.revoke");
    checks.equal(
        &tx.rsvp().revoke_for_object(populated.object).await?,
        &0,
        "rsvp.revoke_for_object",
    );
    checks.equal(
        &tx.rsvp()
            .revoke_for_attendee(populated.object, &populated.attendee)
            .await?,
        &0,
        "rsvp.revoke_for_attendee",
    );
    checks.equal(
        &tx.rsvp().revoke_for_address(&populated.attendee).await?,
        &0,
        "rsvp.revoke_for_address",
    );

    checks.not_found(tx.outbox().requeue(populated.outbox).await, "outbox.requeue");
    checks.not_found(
        tx.webhooks()
            .update(super::delivery::subscription_for(0xB01, &[])?, 1)
            .await,
        "webhooks.update",
    );
    checks.not_found(tx.webhooks().delete(populated.webhook).await, "webhooks.delete");
    checks.not_found(
        tx.webhooks().record_success(populated.webhook).await,
        "webhooks.record_success",
    );
    checks.not_found(
        tx.webhooks().record_failure(populated.webhook).await,
        "webhooks.record_failure",
    );
    checks.not_found(tx.webhooks().disable(populated.webhook, "x").await, "webhooks.disable");
    checks.not_found(
        tx.webhooks()
            .create_delivery(super::delivery::delivery_for(0xC09, populated.webhook))
            .await,
        "webhooks.create_delivery",
    );
    checks.not_found(
        tx.webhooks()
            .update_delivery(super::delivery::delivery_for(0xC01, populated.webhook), 1)
            .await,
        "webhooks.update_delivery",
    );
    checks.not_found(
        tx.external_accounts()
            .create(super::delivery::account_for(0xD09, world.olivia, "google", None))
            .await,
        "external_accounts.create",
    );
    checks.not_found(
        tx.external_accounts()
            .update(super::delivery::account_for(0xD01, world.olivia, "google", None), 1)
            .await,
        "external_accounts.update",
    );
    checks.not_found(
        tx.external_accounts().delete(populated.account).await,
        "external_accounts.delete",
    );
    checks.not_found(
        tx.oauth_states()
            .create(super::delivery::oauth_state_for(0xE09, world.olivia, 9, far_future()))
            .await,
        "oauth_states.create",
    );
    checks.not_found(
        tx.idempotency()
            .complete(id(0x710), "key-1", 200, Some(serde_json::json!({"hijacked": true})))
            .await,
        "idempotency.complete",
    );
    checks.that(
        tx.idempotency().release(id(0x710), "key-1").await.is_ok(),
        "idempotency.release (the key of another tenant is no key of this one: nothing to release, no error)",
    );
    checks.not_found(
        tx.idempotency()
            .complete_leased(id(0x710), "key-1", far_future(), 200, None)
            .await,
        "idempotency.complete_leased",
    );
    checks.that(
        tx.idempotency()
            .release_leased(id(0x710), "key-1", far_future())
            .await
            .is_ok(),
        "idempotency.release_leased (nothing to release in this tenant, no error)",
    );
    drop(tx);

    // The first tenant did not notice.
    let mut tx = begin(db, world.a).await?;
    let IdempotencyClaim::Existing(key_of_a) = tx.idempotency().claim(request(id(0x710), "key-1")).await? else {
        checks.fail("the idempotency key of the first tenant was released by the second");
        return Ok(());
    };
    checks.equal(
        &(key_of_a.status, key_of_a.response_status),
        &(IdempotencyStatus::InFlight, None),
        "the idempotency key is still in flight and was not completed",
    );
    let olivia_after = tx.principals().get(world.olivia).await?;
    checks.equal(&olivia_after.credential_generation, &0, "the principal is unchanged");
    checks.equal(
        &tx.principals().addresses(world.olivia).await?.len(),
        &1,
        "its addresses too",
    );
    checks.equal(
        &tx.calendars().get(world.personal).await?.sync_seq,
        &1,
        "the calendar keeps its sequence",
    );
    checks.equal(
        &tx.objects().get(world.personal, &populated.object_uri).await?.id,
        &populated.object,
        "the object stays",
    );
    checks.that(
        tx.credentials()
            .get_app_password(populated.app_password)
            .await?
            .revoked_at
            .is_none(),
        "the credentials are not revoked",
    );
    checks.that(
        tx.rsvp().get(populated.rsvp).await?.revoked_at.is_none(),
        "the RSVP token is not revoked",
    );
    checks.equal(
        &tx.webhooks().get(populated.webhook).await?.failure_count,
        &0,
        "the webhook counters are untouched",
    );
    checks.equal(
        &tx.bindings().get(populated.binding).await?.version,
        &1,
        "the binding is untouched",
    );
    checks.equal(
        &tx.grants().get(populated.grant).await?.status,
        &GrantStatus::Accepted,
        "the grant is untouched",
    );
    checks.equal(
        &tx.outbox().get(populated.outbox).await?.status,
        &davhaven_ports::OutboxStatus::Pending,
        "the outbox record is untouched",
    );
    Ok(())
}

/// Entities cannot pick the tenant they are stored in.
pub(super) async fn entities_cannot_choose_their_tenant(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let mut tx = begin(db, world.a).await?;
    let mut stray = principal(0x160, "stray", PrincipalKind::User)?;
    stray.tenant_id = world.b;
    let stored = tx.principals().create(stray).await?;
    checks.equal(
        &stored.tenant_id,
        &world.a,
        "a principal that names another tenant is stored in the transaction's tenant",
    );
    let mut calendar_entity = calendar(0x380, stored.id, "stray", CalendarKind::User)?;
    calendar_entity.tenant_id = world.b;
    let stored_calendar = tx.calendars().create(calendar_entity).await?;
    checks.equal(&stored_calendar.tenant_id, &world.a, "and so is a calendar");
    let mut note = notification(0x890, stored.id, "n.xml", "n")?;
    note.tenant_id = world.b;
    checks.equal(
        &tx.notifications().create(note).await?.tenant_id,
        &world.a,
        "and a notification",
    );
    let mut password = app_password(0x790, stored.id, "stray-pass");
    password.tenant_id = world.b;
    checks.equal(
        &tx.credentials().create_app_password(password).await?.tenant_id,
        &world.a,
        "and a credential",
    );
    tx.commit().await?;

    let mut other = begin(db, world.b).await?;
    checks.not_found(
        other.principals().get(stored.id).await,
        "the other tenant never sees it",
    );
    checks.equal(
        &other
            .principals()
            .list(&PrincipalFilter::default(), PageReq::default())
            .await?
            .items
            .len(),
        &1,
        "its own list is unchanged",
    );
    Ok(())
}

/// A transaction of a tenant that does not exist reads nothing and cannot write rows.
pub(super) async fn unknown_tenants(db: &Db, checks: &mut Checks) -> Outcome {
    let world = seed(db).await?;
    let ghost = id(0xDEAD);
    let mut tx = begin(db, ghost).await?;
    checks.not_found(tx.tenant().get().await, "the tenant row");
    checks.not_found(tx.principals().get(world.olivia).await, "a principal");
    checks.equal(
        &tx.principals()
            .list(&PrincipalFilter::default(), PageReq::default())
            .await?
            .items
            .len(),
        &0,
        "the principal list",
    );
    checks.equal(
        &tx.outbox()
            .list(&OutboxFilter::default(), PageReq::default())
            .await?
            .items
            .len(),
        &0,
        "the outbox",
    );
    checks.not_found(
        tx.principals()
            .create(principal(0x170, "ghost", PrincipalKind::User)?)
            .await,
        "creating a principal",
    );
    checks.not_found(
        tx.outbox()
            .enqueue(NewOutbox::now(id(0xA01), OutboxMessage::ProviderPush(Reserved {})))
            .await,
        "enqueueing an outbox message",
    );
    checks.not_found(
        tx.idempotency().claim(request(id(0x710), "k")).await.map(|_| ()),
        "claiming an idempotency key",
    );
    tx.audit()
        .append(NewAudit {
            id: uuid(1),
            actor: AuditActor::system(),
            event: AuditEvent::TenantDeleted,
        })
        .await?;
    tx.commit().await?;
    let mut tx = begin(db, ghost).await?;
    checks.equal(
        &tx.audit()
            .list(&AuditFilter::default(), PageReq::default())
            .await?
            .items
            .len(),
        &1,
        "the audit log has no tenant key: records of a deleted tenant stay readable",
    );
    Ok(())
}

/// Every operation of [`TENANT_OPERATIONS`] was really called with the ids of another tenant: the reads and the
/// writes run in one case, and each listed operation must have a check that ran under its name (a label that merely
/// appears in the source, in a comment or in code that was skipped, does not count). Operations in `INDIRECT` are
/// shown by the cases that create rows and are not labelled with the operation name.
pub(super) async fn isolation_covers_every_operation(db: &Db, checks: &mut Checks) -> Outcome {
    let populated = populate(db).await?;
    reads(db, &populated, checks).await?;
    writes(db, &populated, checks).await?;
    for operation in TENANT_OPERATIONS {
        if INDIRECT.contains(operation) {
            continue;
        }
        let ran = checks.ran(operation);
        checks.that(
            ran,
            &format!("{operation} was called with the ids of another tenant (no check ran under its name)"),
        );
    }
    Ok(())
}

/// Every operation of the tenant-bound repositories, named as the store adapters name it for `observe`
/// (`repository.method`). The isolation cases call each of them with the ids of another tenant; the adapters
/// check that every operation they implement is listed here, so a new repository method cannot be added without
/// an isolation case (`ENGINEERING_RULES` R4).
pub const TENANT_OPERATIONS: &[&str] = &[
    "audit.append",
    "audit.list",
    "bindings.create",
    "bindings.delete",
    "bindings.find_for_calendar",
    "bindings.find_for_calendars",
    "bindings.get",
    "bindings.get_by_slug",
    "bindings.list_for",
    "bindings.list_for_calendar",
    "bindings.update",
    "calendars.access_facts",
    "calendars.access_facts_many",
    "calendars.create",
    "calendars.get",
    "calendars.get_by_slug",
    "calendars.get_many",
    "calendars.list",
    "calendars.list_owned",
    "calendars.lock",
    "calendars.purge",
    "calendars.soft_delete",
    "calendars.touch",
    "calendars.update",
    "calendars.visible_without_binding",
    "changes.since",
    "changes.state",
    "changes.touch_home",
    "changes.touch_inbox",
    "changes.touch_notifications",
    "credentials.create_api_token",
    "credentials.create_app_password",
    "credentials.create_feed_token",
    "credentials.get_api_token",
    "credentials.get_app_password",
    "credentials.get_feed_token",
    "credentials.list_api_tokens",
    "credentials.list_app_passwords",
    "credentials.list_feed_tokens",
    "credentials.rehash",
    "credentials.revoke_all_for_principal",
    "credentials.revoke_api_token",
    "credentials.revoke_app_password",
    "credentials.revoke_feed_token",
    "credentials.touch_last_used",
    "external_accounts.create",
    "external_accounts.delete",
    "external_accounts.get",
    "external_accounts.list",
    "external_accounts.update",
    "grants.create",
    "grants.delete",
    "grants.find",
    "grants.find_by_invite_uid",
    "grants.for_calendar",
    "grants.for_calendars",
    "grants.for_grantee",
    "grants.get",
    "grants.update",
    "idempotency.claim",
    "idempotency.claim_leased",
    "idempotency.complete",
    "idempotency.complete_leased",
    "idempotency.release",
    "idempotency.release_leased",
    "inbox.create",
    "inbox.delete",
    "inbox.get",
    "inbox.get_by_uri",
    "inbox.get_many_by_uri",
    "inbox.list",
    "memberships.add_member",
    "memberships.groups_of",
    "memberships.groups_of_many",
    "memberships.members",
    "memberships.members_of_many",
    "memberships.remove_member",
    "memberships.set_members",
    "notifications.create",
    "notifications.delete",
    "notifications.find_by_uid",
    "notifications.get",
    "notifications.get_by_uri",
    "notifications.get_many_by_uri",
    "notifications.list",
    "notifications.update",
    "oauth_states.consume",
    "oauth_states.create",
    "objects.attendees",
    "objects.delete",
    "objects.find_scheduling_uid",
    "objects.get",
    "objects.get_by_external_key",
    "objects.get_by_id",
    "objects.get_by_uid",
    "objects.list",
    "objects.list_index",
    "objects.move_to",
    "objects.put",
    "objects.query",
    "objects.query_index",
    "objects.uri_for_scheduling_uid",
    "objects.uri_for_uid",
    "outbox.enqueue",
    "outbox.get",
    "outbox.list",
    "outbox.requeue",
    "principals.addresses",
    "principals.addresses_many",
    "principals.bump_credential_generation",
    "principals.create",
    "principals.find_by_address",
    "principals.find_by_addresses",
    "principals.find_by_external_ref",
    "principals.get",
    "principals.get_by_name",
    "principals.get_many",
    "principals.get_many_by_name",
    "principals.list",
    "principals.purge",
    "principals.search",
    "principals.set_addresses",
    "principals.update",
    "properties.count",
    "properties.get",
    "properties.list",
    "properties.list_many",
    "properties.remove",
    "properties.set",
    "rsvp.create",
    "rsvp.find_live",
    "rsvp.for_object",
    "rsvp.get",
    "rsvp.record_use",
    "rsvp.revoke",
    "rsvp.revoke_for_address",
    "rsvp.revoke_for_attendee",
    "rsvp.revoke_for_object",
    "tenant.get",
    "webhooks.create",
    "webhooks.create_delivery",
    "webhooks.delete",
    "webhooks.disable",
    "webhooks.get",
    "webhooks.get_delivery",
    "webhooks.list",
    "webhooks.list_deliveries",
    "webhooks.record_failure",
    "webhooks.record_success",
    "webhooks.subscribed_to",
    "webhooks.update",
    "webhooks.update_delivery",
];

/// Operations whose isolation is shown by a case that does not label the call with the operation name:
/// creating rows (an entity cannot pick its tenant, `entities_cannot_choose_their_tenant`), the own tenant row
/// and the idempotency claim (`foreign_tenant_writes`, `unknown_tenants`).
const INDIRECT: &[&str] = &[
    "audit.append",
    "idempotency.claim",
    "outbox.enqueue",
    "principals.create",
    "tenant.get",
    "webhooks.create",
];

/// The operation names an adapter source file passes to `observed!(...)`, in order of appearance.
fn observed_operations(source: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut rest = source;
    while let Some(at) = rest.find("observed!(") {
        rest = rest.get(at + "observed!(".len()..).unwrap_or_default();
        let trimmed = rest.trim_start();
        if let Some(quoted) = trimmed.strip_prefix('"')
            && let Some((name, _)) = quoted.split_once('"')
        {
            found.push(name);
        }
    }
    found
}

/// Fails unless every repository method of a store adapter's tenant-bound modules has an isolation case.
///
/// `sources` are the adapter's source files as `(file name, text)`; the operations are the names they pass to
/// `observed!`. A method added to an adapter without an entry in [`TENANT_OPERATIONS`] (and so without a case in
/// this module) makes the adapter's own tests fail: the isolation coverage of R4 cannot be forgotten.
///
/// # Panics
///
/// When a source file names an operation that is not listed.
pub fn assert_isolation_covers(sources: &[(&str, &str)]) {
    for (file, source) in sources {
        let operations = observed_operations(source);
        assert!(
            !operations.is_empty(),
            "{file}: no `observed!` operations found; is the macro renamed?"
        );
        for operation in operations {
            assert!(
                TENANT_OPERATIONS.contains(&operation),
                "{file}: `{operation}` has no isolation case; call it with the ids of another tenant in \
                 port-tests/src/store/isolation.rs and add it to TENANT_OPERATIONS"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = include_str!("isolation.rs");

    #[test]
    fn operations_are_read_from_the_observed_macro() {
        let source = "observed!(\"a.b\", { 1 })\n  observed!(\n \"c.d\",\n  2)\nobserved!(self.x)";
        assert_eq!(observed_operations(source), vec!["a.b", "c.d"]);
    }

    #[test]
    #[should_panic(expected = "has no isolation case")]
    fn an_unlisted_operation_is_refused() {
        assert_isolation_covers(&[("x.rs", "observed!(\"widgets.frobnicate\", { 1 })")]);
    }

    #[test]
    fn the_operation_list_is_sorted_and_free_of_duplicates() {
        let mut sorted = TENANT_OPERATIONS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, TENANT_OPERATIONS);
    }

    #[test]
    fn every_listed_operation_has_a_labelled_isolation_check() {
        // Only the cases count, not the list itself (which names every operation).
        let (cases, _) = SOURCE
            .split_once("/// Every operation of the tenant-bound repositories")
            .expect("the list follows the cases");
        for operation in TENANT_OPERATIONS {
            let labelled = cases.contains(&format!("\"{operation}\"")) || cases.contains(&format!("\"{operation} "));
            assert!(
                labelled || INDIRECT.contains(operation),
                "{operation} is listed as covered by isolation.rs but no check carries its name"
            );
        }
    }
}
