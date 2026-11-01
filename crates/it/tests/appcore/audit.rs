//! The audit log: records are written in the transaction of the change, listings filter and page, actors are
//! recorded without addresses, and details carry ids and counts, never content.

use std::net::{IpAddr, Ipv4Addr};

use davhaven_testkit::davhaven_app::services::{AuditFilter, PageRequest};
use davhaven_testkit::davhaven_domain::{
    AuditActorKind, CalendarKind, CredentialKind, CredentialRef, ErrorKind, EventType, RequestContext, Scope, ScopeSet,
};
use davhaven_testkit::davhaven_wire::AppPasswordCreate;
use chrono::Duration;

use super::support::{Fixture, World, fixture, principal_body};

async fn count(world: &World, org: &super::support::Org) -> usize {
    world.audit(org).await.len()
}

#[tokio::test]
async fn an_audited_change_and_its_record_commit_or_vanish_together() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let admin = world.admin(&acme);
    let create = |label: &str| {
        let world = &world;
        let admin = admin.clone();
        let name = anna.name.clone();
        let label = label.to_owned();
        async move {
            world
                .services
                .credentials
                .create_app_password(&admin, &name, AppPasswordCreate { label })
                .await
        }
    };
    let before = count(&world, &acme).await;

    // Lost commits: the change is not there and neither is its record.
    world.faults.fail_next_commits(3);
    assert_eq!(create("lost").await.unwrap_err().kind(), ErrorKind::Unavailable);
    assert_eq!(count(&world, &acme).await, before);
    assert!(
        world
            .services
            .credentials
            .list_app_passwords(&admin, &anna.name, PageRequest::first())
            .await
            .unwrap()
            .items
            .is_empty()
    );

    // A commit that is lost once and then wins leaves exactly one of each.
    world.faults.fail_next_commits(1);
    create("retried").await.unwrap();
    assert_eq!(count(&world, &acme).await, before + 1);
    assert_eq!(
        world
            .services
            .credentials
            .list_app_passwords(&admin, &anna.name, PageRequest::first())
            .await
            .unwrap()
            .items
            .len(),
        1
    );

    // A refused request leaves nothing.
    assert_eq!(create("   ").await.unwrap_err().kind(), ErrorKind::Invalid);
    assert_eq!(count(&world, &acme).await, before + 1);

    // The same holds for the domain event of a change: it is in the outbox with the change or not at all.
    let events = world.events(&acme).await.len();
    world.faults.fail_next_commits(3);
    let body = principal_body(&acme, "carla", davhaven_testkit::davhaven_domain::PrincipalKind::User);
    assert_eq!(
        world
            .principal_write(&acme, "carla", body.clone())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Unavailable
    );
    assert_eq!(world.events(&acme).await.len(), events);
    assert_eq!(count(&world, &acme).await, before + 1);
    world.principal_write(&acme, "carla", body).await.unwrap();
    assert_eq!(
        world.events_of(&acme, EventType::PrincipalCreated).await.len(),
        3,
        "anna, ben and carla"
    );
    assert_eq!(count(&world, &acme).await, before + 2);
}

#[tokio::test]
async fn the_audit_log_is_listed_in_pages_with_filters() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let admin = world.admin(&acme);
    let start = world.now();
    world.clock.advance(Duration::hours(1));
    world.user(&acme, "carla").await;
    world.clock.advance(Duration::hours(1));
    world
        .services
        .credentials
        .create_app_password(
            &admin,
            &anna.name,
            AppPasswordCreate {
                label: "phone".to_owned(),
            },
        )
        .await
        .unwrap();
    let list = |filter: AuditFilter, page: PageRequest| {
        let world = &world;
        let admin = admin.clone();
        async move { world.services.audit.list(&admin, filter, page).await }
    };

    // Everything in order, in pages.
    let all = list(AuditFilter::default(), PageRequest::first()).await.unwrap();
    let actions: Vec<&str> = all.items.iter().map(|view| view.action.as_str()).collect();
    assert_eq!(
        actions,
        vec![
            "tenant.created",
            "principal.created",
            "principal.created",
            "principal.created",
            "credential.created"
        ]
    );
    let mut seen = Vec::new();
    let mut page = PageRequest::with_limit(2);
    loop {
        let batch = list(AuditFilter::default(), page.clone()).await.unwrap();
        assert!(batch.items.len() <= 2);
        seen.extend(batch.items.iter().map(|view| view.id));
        match batch.next_cursor {
            Some(cursor) => page = PageRequest::with_limit(2).after(cursor),
            None => break,
        }
    }
    assert_eq!(seen, all.items.iter().map(|view| view.id).collect::<Vec<_>>());

    // Filters.
    let created = list(
        AuditFilter {
            action: Some("principal.created".to_owned()),
            ..AuditFilter::default()
        },
        PageRequest::first(),
    )
    .await
    .unwrap();
    assert_eq!(created.items.len(), 3);
    let target = created.items[0]
        .target
        .clone()
        .expect("a principal event names its target");
    let by_target = list(
        AuditFilter {
            target: Some(target.clone()),
            ..AuditFilter::default()
        },
        PageRequest::first(),
    )
    .await
    .unwrap();
    assert_eq!(by_target.items.len(), 1);
    assert_eq!(by_target.items[0].id, created.items[0].id);
    let late = list(
        AuditFilter {
            since: Some(start + Duration::minutes(90)),
            ..AuditFilter::default()
        },
        PageRequest::first(),
    )
    .await
    .unwrap();
    assert_eq!(
        late.items.iter().map(|view| view.action.as_str()).collect::<Vec<_>>(),
        vec!["credential.created"]
    );
    let middle = list(
        AuditFilter {
            since: Some(start + Duration::minutes(30)),
            until: Some(start + Duration::minutes(90)),
            ..AuditFilter::default()
        },
        PageRequest::first(),
    )
    .await
    .unwrap();
    assert_eq!(middle.items.len(), 1);
    assert_eq!(middle.items[0].action, "principal.created");
    assert!(middle.items[0].at >= start + Duration::minutes(30));

    // Unusable filters.
    let backwards = list(
        AuditFilter {
            since: Some(start + Duration::hours(2)),
            until: Some(start),
            ..AuditFilter::default()
        },
        PageRequest::first(),
    )
    .await
    .unwrap_err();
    assert_eq!(
        backwards.field_errors().first().map(|field| field.pointer),
        Some("/until")
    );
    for filter in [
        AuditFilter {
            action: Some("x".repeat(201)),
            ..AuditFilter::default()
        },
        AuditFilter {
            target: Some("bad\u{7}".to_owned()),
            ..AuditFilter::default()
        },
    ] {
        assert_eq!(
            list(filter, PageRequest::first()).await.unwrap_err().kind(),
            ErrorKind::Invalid
        );
    }
}

#[tokio::test]
async fn reading_the_audit_log_needs_its_scope_and_other_tenants_see_none_of_it() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let other = world.org("other").await;
    let reader = world.tenant_token(&acme, ScopeSet::of(&[Scope::AuditRead]));
    assert!(
        !world
            .services
            .audit
            .list(&reader, AuditFilter::default(), PageRequest::first())
            .await
            .unwrap()
            .items
            .is_empty()
    );
    for (name, ctx) in [
        (
            "another scope",
            world.tenant_token(&acme, ScopeSet::of(&[Scope::PrincipalsRead])),
        ),
        ("a DAV session", world.dav(&acme, &anna)),
        (
            "a principal token",
            world.api(&acme, &anna, &[Scope::CalendarsRead, Scope::EventsRead]),
        ),
    ] {
        let error = world
            .services
            .audit
            .list(&ctx, AuditFilter::default(), PageRequest::first())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Forbidden, "{name}");
    }
    let foreign = world.tenant_token(&other, ScopeSet::of(&[Scope::AuditRead]));
    let theirs = world
        .services
        .audit
        .list(&foreign, AuditFilter::default(), PageRequest::first())
        .await
        .unwrap();
    assert!(
        theirs.items.iter().all(|view| view.action == "tenant.created"),
        "{theirs:?}"
    );
}

#[tokio::test]
async fn actors_are_recorded_by_kind_and_id_and_addresses_only_as_keyed_hashes() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let ip = |last: u8| Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, last)));
    let admin = world.stored_admin(&acme).await;
    let from = |ctx: &RequestContext, address| RequestContext {
        client_ip: address,
        ..ctx.clone()
    };
    let mint = |ctx: RequestContext| {
        let world = &world;
        let name = anna.name.clone();
        async move {
            world
                .services
                .credentials
                .create_app_password(&ctx, &name, AppPasswordCreate { label: "x".to_owned() })
                .await
                .unwrap();
        }
    };
    let first_count = count(&world, &acme).await;
    mint(from(&admin, ip(1))).await;
    mint(from(&admin, ip(1))).await;
    mint(from(&admin, ip(2))).await;
    mint(from(&admin, None)).await;
    let rows: Vec<_> = world.audit(&acme).await.into_iter().skip(first_count).collect();
    assert_eq!(rows.len(), 4);
    for row in &rows {
        assert_eq!(row.actor.kind, AuditActorKind::TenantToken);
        assert_eq!(row.actor.token_id, admin.actor.token());
        assert_eq!(row.actor.principal_id, None);
    }
    let hashes: Vec<Option<String>> = rows.iter().map(|row| row.actor.ip_hash.clone()).collect();
    assert!(
        hashes[0]
            .as_ref()
            .is_some_and(|hash| hash.len() == 16 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
    );
    assert_eq!(hashes[0], hashes[1], "the same address, the same hash");
    assert_ne!(hashes[0], hashes[2], "another address, another hash");
    assert_eq!(hashes[3], None);
    assert!(
        !format!("{rows:?}").contains("203.0.113"),
        "the address itself is never stored"
    );

    // A DAV user is recorded by principal id.
    let ben = world.user(&acme, "ben").await;
    world
        .services
        .sharing
        .share(
            &world.dav(&acme, &anna),
            &world.collection(&acme, &anna, "personal"),
            davhaven_testkit::davhaven_app::services::ShareRequest {
                set: vec![davhaven_testkit::davhaven_app::services::ShareeSet {
                    address: davhaven_testkit::davhaven_domain::CalendarUserAddress::parse("mailto:ben@acme.example")
                        .unwrap(),
                    common_name: None,
                    summary: Some("Confidential summary".to_owned()),
                    access: davhaven_testkit::davhaven_domain::GrantAccess::Read,
                }],
                remove: Vec::new(),
            },
        )
        .await
        .unwrap();
    let invited = world
        .audit(&acme)
        .await
        .into_iter()
        .find(|row| row.action == "share.invited")
        .expect("the invitation is recorded");
    assert_eq!(invited.actor.kind, AuditActorKind::Principal);
    assert_eq!(invited.actor.principal_id, Some(anna.id));
    let _ = ben;
}

#[tokio::test]
async fn audit_details_carry_ids_and_counts_never_content_or_addresses() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let mut body = principal_body(&acme, "carla", davhaven_testkit::davhaven_domain::PrincipalKind::User);
    body.display_name = "Carla Confidential".to_owned();
    body.external_ref = Some("hr-secret-42".to_owned());
    world.principal_write(&acme, "carla", body).await.unwrap();
    world
        .services
        .sharing
        .share(
            &world.dav(&acme, &anna),
            &world.collection(&acme, &anna, "personal"),
            davhaven_testkit::davhaven_app::services::ShareRequest {
                set: vec![davhaven_testkit::davhaven_app::services::ShareeSet {
                    address: davhaven_testkit::davhaven_domain::CalendarUserAddress::parse("mailto:ben@acme.example")
                        .unwrap(),
                    common_name: Some("Ben Confidential".to_owned()),
                    summary: Some("Confidential summary".to_owned()),
                    access: davhaven_testkit::davhaven_domain::GrantAccess::Read,
                }],
                remove: Vec::new(),
            },
        )
        .await
        .unwrap();
    let _ = ben;
    let text = format!("{:?}", world.audit(&acme).await);
    for secret in [
        "Carla Confidential",
        "hr-secret-42",
        "Ben Confidential",
        "Confidential summary",
        "carla@acme.example",
        "ben@acme.example",
    ] {
        assert!(!text.contains(secret), "{secret} must not be in the audit log: {text}");
    }
}

fn from_token(ctx: &RequestContext, ip: Option<IpAddr>) -> RequestContext {
    let token = ctx.actor.token().unwrap();
    RequestContext {
        credential: Some(CredentialRef {
            kind: CredentialKind::ApiToken,
            id: token.as_uuid(),
        }),
        client_ip: ip,
        ..ctx.clone()
    }
}

#[tokio::test]
async fn records_name_the_credential_the_request_used_and_events_do_not() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let admin = world.stored_admin(&acme).await;
    let ip = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
    let ctx = from_token(&admin, ip);
    let before = count(&world, &acme).await;
    world
        .services
        .credentials
        .create_app_password(&ctx, &anna.name, AppPasswordCreate { label: "x".to_owned() })
        .await
        .unwrap();
    world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    world
        .services
        .calendars
        .upsert(
            &ctx,
            davhaven_testkit::davhaven_app::services::CalendarSpec {
                owner: anna.name.clone(),
                slug: davhaven_testkit::davhaven_domain::CalendarSlug::parse("second").unwrap(),
                body: davhaven_testkit::davhaven_wire::CalendarWrite {
                    kind: Some(CalendarKind::User),
                    display_name: "Second".to_owned(),
                    description: None,
                    color: None,
                    sort_order: None,
                    components: None,
                },
            },
            davhaven_testkit::davhaven_app::services::Conditions::none(),
        )
        .await
        .unwrap();

    // The audit log tells an operator which credential did it and from which (hashed) address.
    let rows: Vec<_> = world.audit(&acme).await.into_iter().skip(before).collect();
    let mine = rows
        .iter()
        .find(|row| row.action == "credential.created")
        .expect("the creation is recorded");
    assert_eq!(mine.actor.label.as_deref(), Some("seeded"), "the label of the token");
    assert!(mine.actor.ip_hash.is_some());

    // The events go to third parties: who and which token, never the operator's information.
    let events = world.events_of(&acme, EventType::CalendarCreated).await;
    let event = events.last().expect("the creation is announced");
    assert_eq!(event.actor.token_id, ctx.actor.token());
    assert_eq!(event.actor.label, None);
    assert_eq!(event.actor.ip_hash, None);
}

#[tokio::test]
async fn the_hash_of_an_address_is_not_the_same_in_two_tenants() {
    let world = World::new();
    let acme = world.org("acme").await;
    let other = world.org("other").await;
    let anna = world.user(&acme, "anna").await;
    let olga = world.user(&other, "olga").await;
    let ip = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)));
    let mut hashes = Vec::new();
    for (org, person) in [(&acme, &anna), (&other, &olga)] {
        let admin = from_token(&world.stored_admin(org).await, ip);
        world
            .services
            .credentials
            .create_app_password(&admin, &person.name, AppPasswordCreate { label: "x".to_owned() })
            .await
            .unwrap();
        let row = world
            .audit(org)
            .await
            .into_iter()
            .find(|row| row.action == "credential.created")
            .unwrap();
        hashes.push(row.actor.ip_hash.unwrap());
    }
    assert_ne!(
        hashes[0], hashes[1],
        "an operator who sees two tenants' logs cannot tell that one address made both requests"
    );
}
