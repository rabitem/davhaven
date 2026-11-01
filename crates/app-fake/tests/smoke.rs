//! Smoke tests of the fake services: authentication, principals, homes, objects, sync, JSON events and batch.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use davhaven_app::services::{
    AddressClass, AuthRequest, CalendarDataSpec, CalendarRef, Conditions, CopyRequest, DeleteEventOptions,
    DeleteOutcome, DeleteRequest, EventSearch, EventWrite, MergePatch, MoveRequest, MultigetEntry, ObjectFilter,
    ObjectSelector, PageRequest, PresentedCredential, PrincipalFilter, PrincipalSearch, PrincipalSpec, PutRequest,
    ScheduleReply, SecretString, SyncResult, WritePrecondition,
};
use davhaven_app::{AppServices, error::AppResult};
use davhaven_app_fake::{AppServicesExt as _, FakeApp, seed};
use davhaven_domain::{
    CalendarKind, CalendarSlug, CalendarUserAddress, Channel, ETag, ErrorKind, ExternalKey, Precondition,
    PrincipalKind, PrincipalName, RequestContext, RequestId, ResourcePath, SyncToken, TenantId, TenantSlug, Uid,
};
use davhaven_wire::mcp::ChangeScope;
use davhaven_wire::{BatchItem, BatchMode, BatchOutcome, BatchRequest, EventView, PrincipalWrite};
use uuid::Uuid;

fn request(channel: Channel, credential: PresentedCredential, hint: Option<&str>) -> AuthRequest {
    AuthRequest {
        channel,
        tenant_hint: hint.map(|slug| TenantSlug::parse(slug).unwrap()),
        credential,
        client_ip: None,
        request_id: RequestId::from_uuid(Uuid::nil()),
    }
}

fn basic(login: &str, password: &str) -> PresentedCredential {
    PresentedCredential::Basic {
        username: login.to_owned(),
        password: SecretString::from(password),
    }
}

fn bearer(secret: &str) -> PresentedCredential {
    PresentedCredential::Bearer(SecretString::from(secret))
}

async fn login(services: &AppServices, login: &str, password: &str) -> RequestContext {
    services
        .auth
        .authenticate(request(Channel::Dav, basic(login, password), None))
        .await
        .unwrap()
}

async fn api(services: &AppServices, secret: &str) -> RequestContext {
    services
        .auth
        .authenticate(request(Channel::Api, bearer(secret), Some(seed::TENANT)))
        .await
        .unwrap()
}

fn path(text: &str) -> ResourcePath {
    ResourcePath::parse(text).unwrap()
}

fn name(text: &str) -> PrincipalName {
    PrincipalName::parse(text).unwrap()
}

fn kind_of<T>(result: AppResult<T>) -> ErrorKind {
    result.err().expect("the call must fail").kind()
}

fn put(text: &str, body: &str) -> PutRequest {
    PutRequest {
        path: path(text),
        body: body.to_owned(),
        content_type: Some("text/calendar; charset=utf-8".to_owned()),
        preconditions: WritePrecondition::none(),
        schedule_reply: ScheduleReply::Send,
    }
}

fn lunch() -> String {
    seed::STANDUP_ICS
        .replace("standup-1@acme.example", "lunch-1@acme.example")
        .replace("Standup", "Lunch")
}

#[tokio::test]
async fn credentials_are_bound_to_their_surface() {
    let services = AppServices::fake();
    let anna = login(&services, "anna@acme.example", seed::ANNA_PASSWORD).await;
    assert!(matches!(anna.actor, davhaven_domain::Actor::Principal(_)));
    assert_eq!(anna.channel, Channel::Dav);

    let attempts = [
        (Channel::Api, basic("anna@acme.example", seed::ANNA_PASSWORD), None),
        (Channel::Dav, basic("anna@acme.example", "wrong"), None),
        (Channel::Dav, basic("cara@acme.example", seed::CARA_PASSWORD), None),
        (Channel::Dav, basic("anna", seed::ANNA_PASSWORD), None),
        (Channel::Dav, bearer(seed::ADMIN_TOKEN), Some(seed::TENANT)),
        (Channel::Api, bearer("dvh_pat_unknown_secret"), None),
        (Channel::Feed, bearer(seed::ADMIN_TOKEN), None),
    ];
    for (channel, credential, hint) in attempts {
        let result = services.auth.authenticate(request(channel, credential, hint)).await;
        assert_eq!(kind_of(result), ErrorKind::Unauthenticated);
    }

    // A valid credential on the path of another tenant is authenticated, and then the resources there are invisible
    // to it (R4): 404, not 401.
    for (channel, credential) in [
        (Channel::Dav, basic("anna@acme.example", seed::ANNA_PASSWORD)),
        (Channel::Api, bearer(seed::ADMIN_TOKEN)),
    ] {
        let result = services
            .auth
            .authenticate(request(channel, credential, Some(seed::OTHER_TENANT)))
            .await;
        assert_eq!(kind_of(result), ErrorKind::NotFound, "{channel}");
    }

    let bare = services
        .auth
        .authenticate(request(
            Channel::Dav,
            basic("Anna", seed::ANNA_PASSWORD),
            Some(seed::TENANT),
        ))
        .await
        .unwrap();
    assert_eq!(bare.principal(), anna.principal());

    let admin = api(&services, seed::ADMIN_TOKEN).await;
    assert!(matches!(admin.actor, davhaven_domain::Actor::TenantToken(_)));
    assert!(admin.scopes.contains(davhaven_domain::Scope::PrincipalsRead));
    assert!(!admin.scopes.contains(davhaven_domain::Scope::SystemTenants));

    let system = services
        .auth
        .authenticate(request(Channel::Api, bearer(seed::SYSTEM_TOKEN), None))
        .await
        .unwrap();
    assert!(matches!(system.actor, davhaven_domain::Actor::SystemToken(_)));
    assert_eq!(system.tenant, TenantId::from_uuid(Uuid::nil()));
    let hinted = services
        .auth
        .authenticate(request(Channel::Api, bearer(seed::SYSTEM_TOKEN), Some(seed::TENANT)))
        .await
        .unwrap();
    assert_eq!(hinted.tenant, admin.tenant);
}

#[tokio::test]
async fn feed_and_rsvp_tokens_authenticate_on_their_pages() {
    let app = FakeApp::standard();
    let (tenant, anna) = app
        .state
        .read(|world| {
            let tenant = world
                .tenant_by_slug(&TenantSlug::parse(seed::TENANT).unwrap())
                .unwrap()
                .id;
            (
                tenant,
                world
                    .principal_id(&TenantSlug::parse(seed::TENANT).unwrap(), &name("anna"))
                    .unwrap(),
            )
        })
        .await;
    app.state
        .write(|world| {
            world.add_feed_token(tenant, anna, "dvh_feed_secret");
            world.add_rsvp_token(
                tenant,
                davhaven_domain::ObjectId::from_uuid(Uuid::from_u128(77)),
                CalendarUserAddress::parse("mailto:guest@elsewhere.example").unwrap(),
                "dvh_rsvp_secret",
            );
        })
        .await;
    let feed = app
        .services
        .auth
        .authenticate(request(
            Channel::Feed,
            PresentedCredential::Feed(SecretString::from("dvh_feed_secret")),
            None,
        ))
        .await
        .unwrap();
    assert!(matches!(feed.actor, davhaven_domain::Actor::FeedReader { .. }));
    let rsvp = app
        .services
        .auth
        .authenticate(request(
            Channel::Rsvp,
            PresentedCredential::Rsvp(SecretString::from("dvh_rsvp_secret")),
            None,
        ))
        .await
        .unwrap();
    assert!(matches!(rsvp.actor, davhaven_domain::Actor::RsvpAttendee { .. }));
    let wrong_page = app
        .services
        .auth
        .authenticate(request(
            Channel::Dav,
            PresentedCredential::Feed(SecretString::from("dvh_feed_secret")),
            None,
        ))
        .await;
    assert_eq!(kind_of(wrong_page), ErrorKind::Unauthenticated);
}

#[tokio::test]
async fn administrators_manage_principals() {
    let services = AppServices::fake();
    let admin = api(&services, seed::ADMIN_TOKEN).await;
    let listed = services
        .principals
        .list(&admin, PrincipalFilter::default(), PageRequest::first())
        .await
        .unwrap();
    assert_eq!(listed.items.len(), 6);
    let groups = services
        .principals
        .list(
            &admin,
            PrincipalFilter {
                kind: Some(PrincipalKind::Group),
                external_ref: None,
            },
            PageRequest::first(),
        )
        .await
        .unwrap();
    assert_eq!(groups.items.len(), 1);
    let first = services
        .principals
        .list(&admin, PrincipalFilter::default(), PageRequest::with_limit(4))
        .await
        .unwrap();
    assert_eq!(first.items.len(), 4);
    let second = services
        .principals
        .list(
            &admin,
            PrincipalFilter::default(),
            PageRequest::with_limit(4).after(first.next_cursor.clone().unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(second.items.len(), 2);
    assert!(second.next_cursor.is_none());

    let body: PrincipalWrite =
        serde_json::from_str(r#"{"kind": "user", "display_name": "Dora", "email": "dora@acme.example"}"#).unwrap();
    let spec = PrincipalSpec {
        name: name("dora"),
        body,
    };
    let created = services
        .principals
        .upsert(&admin, spec.clone(), Conditions::create_only())
        .await
        .unwrap();
    assert!(created.created);
    assert_eq!(created.value.version, 1);
    assert!(created.value.dav_url.path().ends_with("/dav/principals/acme/dora/"));
    let again = services
        .principals
        .upsert(&admin, spec.clone(), Conditions::none())
        .await
        .unwrap();
    assert!(!again.created);
    assert_eq!(again.value.version, 1, "an identical write changes nothing");
    assert_eq!(
        kind_of(
            services
                .principals
                .upsert(&admin, spec, Conditions::create_only())
                .await
        ),
        ErrorKind::PreconditionFailed
    );
    let calendars = services
        .calendars
        .list_owned(&admin, &name("dora"), PageRequest::first())
        .await
        .unwrap();
    assert_eq!(calendars.items.len(), 1, "users get a personal calendar");
    assert_eq!(calendars.items[0].kind, CalendarKind::Personal);
}

#[tokio::test]
async fn principals_are_patched_deleted_and_grouped() {
    let services = AppServices::fake();
    let admin = api(&services, seed::ADMIN_TOKEN).await;
    let patch = MergePatch::new(serde_json::json!({"display_name": "Benjamin", "external_ref": "crm-9"})).unwrap();
    let patched = services
        .principals
        .patch(&admin, &name("ben"), patch, Conditions::none())
        .await
        .unwrap();
    assert_eq!(patched.display_name, "Benjamin");
    assert_eq!(patched.external_ref.as_deref(), Some("crm-9"));
    assert_eq!(patched.version, 2);
    let kind_change = MergePatch::new(serde_json::json!({"kind": "group"})).unwrap();
    assert_eq!(
        kind_of(
            services
                .principals
                .patch(&admin, &name("ben"), kind_change, Conditions::none())
                .await
        ),
        ErrorKind::Invalid
    );

    let members = services
        .principals
        .set_members(&admin, &name("team"), vec![name("anna")])
        .await
        .unwrap();
    assert_eq!(members.members, vec![name("anna")]);
    services
        .principals
        .add_member(&admin, &name("team"), &name("ben"))
        .await
        .unwrap();
    assert_eq!(
        services
            .principals
            .members(&admin, &name("team"))
            .await
            .unwrap()
            .members
            .len(),
        2
    );
    services
        .principals
        .remove_member(&admin, &name("team"), &name("anna"))
        .await
        .unwrap();
    assert_eq!(
        services
            .principals
            .members(&admin, &name("team"))
            .await
            .unwrap()
            .members,
        vec![name("ben")]
    );
    assert_eq!(
        kind_of(services.principals.members(&admin, &name("anna")).await),
        ErrorKind::Invalid
    );
    assert_eq!(
        kind_of(
            services
                .principals
                .set_members(&admin, &name("team"), vec![name("nobody")])
                .await
        ),
        ErrorKind::Invalid
    );

    let options = davhaven_app::services::DeleteOptions {
        conditions: Conditions::none(),
        ..Default::default()
    };
    assert_eq!(
        kind_of(services.principals.delete(&admin, &name("ben"), options).await),
        ErrorKind::PreconditionRequired
    );
    let options = davhaven_app::services::DeleteOptions {
        conditions: Conditions::if_match(2),
        ..Default::default()
    };
    services.principals.delete(&admin, &name("ben"), options).await.unwrap();
    assert_eq!(
        kind_of(services.principals.get(&admin, &name("ben")).await),
        ErrorKind::NotFound
    );
    let anna = login(&services, "anna@acme.example", seed::ANNA_PASSWORD).await;
    assert_eq!(
        kind_of(
            services
                .principals
                .list(&anna, PrincipalFilter::default(), PageRequest::first())
                .await
        ),
        ErrorKind::Forbidden,
        "administration needs a tenant token"
    );
}

#[tokio::test]
async fn principals_are_searched_and_resolved() {
    let services = AppServices::fake();
    let anna = login(&services, "anna@acme.example", seed::ANNA_PASSWORD).await;
    let hits = services
        .principals
        .search(&anna, PrincipalSearch::new("ann"))
        .await
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].name, name("anna"));
    assert!(
        hits[0]
            .addresses
            .iter()
            .any(|address| address.as_str() == "mailto:anna@acme.example")
    );
    let short = PrincipalSearch::new("a");
    assert_eq!(
        kind_of(services.principals.search(&anna, short).await),
        ErrorKind::Invalid
    );

    let internal = services
        .principals
        .resolve_address(&anna, &CalendarUserAddress::parse("mailto:Ben@Acme.example").unwrap())
        .await
        .unwrap();
    assert!(matches!(internal, AddressClass::Internal { name: found, .. } if found == name("ben")));
    let external = services
        .principals
        .resolve_address(
            &anna,
            &CalendarUserAddress::parse("mailto:guest@elsewhere.example").unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(external, AddressClass::External);
    let unknown = services
        .principals
        .resolve_address(
            &anna,
            &CalendarUserAddress::parse(&format!("urn:uuid:{}", Uuid::from_u128(999).hyphenated())).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unknown, AddressClass::Unresolvable);

    let props = services
        .principals
        .dav_properties(&anna, &path("/dav/principals/acme/anna/"))
        .await
        .unwrap();
    assert_eq!(props.home, path("/dav/calendars/acme/anna/"));
    assert_eq!(props.group_membership, vec![path("/dav/principals/acme/team/")]);
    assert!(
        props
            .addresses
            .iter()
            .any(|address| address.as_str().starts_with("urn:uuid:"))
    );
    let other_tenant = login(&services, "gina@globex.example", seed::GINA_PASSWORD).await;
    assert_eq!(
        kind_of(
            services
                .principals
                .dav_properties(&other_tenant, &path("/dav/principals/acme/anna/"))
                .await
        ),
        ErrorKind::NotFound
    );

    // The principal a request is authenticated as is found without naming it.
    let own = services.principals.current(&anna).await.unwrap();
    assert_eq!(own.path, path("/dav/principals/acme/anna/"));
    assert_eq!(own.home, props.home);
    let gina = services.principals.current(&other_tenant).await.unwrap();
    assert_eq!(gina.path, path("/dav/principals/globex/gina/"));
    let admin = api(&services, seed::ADMIN_TOKEN).await;
    assert_eq!(
        kind_of(services.principals.current(&admin).await),
        ErrorKind::Unauthenticated,
        "a tenant token acts as no principal"
    );
}

#[tokio::test]
async fn homes_list_owned_and_group_calendars() {
    let services = AppServices::fake();
    let anna = login(&services, "anna@acme.example", seed::ANNA_PASSWORD).await;
    let home = services.calendars.list_home(&anna, &name("anna")).await.unwrap();
    let slugs: Vec<String> = home.iter().map(|binding| binding.path.format()).collect();
    assert_eq!(
        slugs,
        vec![
            "/dav/calendars/acme/anna/personal/",
            "/dav/calendars/acme/anna/team-calendar/",
            "/dav/calendars/acme/anna/work/"
        ]
    );
    let work = &home[2];
    assert_eq!(work.access, davhaven_domain::Access::Owner);
    assert!(work.privileges.contains(davhaven_domain::Privilege::WriteContent));
    assert_eq!(home[1].kind, CalendarKind::Group);
    assert_eq!(home[1].access, davhaven_domain::Access::ReadWrite);

    let collection = services.calendars.get_collection(&anna, &work.path).await.unwrap();
    assert_eq!(collection.sync_token.unwrap().seq, 1);
    assert_eq!(collection.calendar.unwrap().display_name, "Work");
    for special in ["inbox", "outbox", "notifications"] {
        let view = services
            .calendars
            .get_collection(&anna, &path(&format!("/dav/calendars/acme/anna/{special}/")))
            .await
            .unwrap();
        assert!(view.calendar.is_none());
    }

    let ben = login(&services, "ben@acme.example", seed::BEN_PASSWORD).await;
    assert_eq!(
        kind_of(services.calendars.list_home(&ben, &name("anna")).await),
        ErrorKind::NotFound
    );
    assert_eq!(
        kind_of(services.calendars.get_collection(&ben, &work.path).await),
        ErrorKind::NotFound
    );
}

#[tokio::test]
async fn mkcalendar_proppatch_and_delete_follow_the_home_rules() {
    let services = AppServices::fake();
    let anna = login(&services, "anna@acme.example", seed::ANNA_PASSWORD).await;
    let target = path("/dav/calendars/acme/anna/projects/");
    let request = davhaven_app::services::MkCalendar {
        path: target.clone(),
        display_name: Some("Projects".to_owned()),
        description: None,
        color: Some("#336699".to_owned()),
        sort_order: Some(5),
        components: None,
        timezone_ics: None,
        schedule_transp: None,
        dead_properties: Vec::new(),
    };
    let created = services.calendars.mkcalendar(&anna, request.clone()).await.unwrap();
    assert_eq!(created.display_name, "Projects");
    assert_eq!(created.sort_order, 5);
    let again = services.calendars.mkcalendar(&anna, request).await.err().unwrap();
    assert_eq!(again.kind(), ErrorKind::Conflict);
    assert_eq!(again.precondition(), Some(&Precondition::ResourceMustBeNull));

    let ben = login(&services, "ben@acme.example", seed::BEN_PASSWORD).await;
    let foreign = davhaven_app::services::MkCalendar {
        path: path("/dav/calendars/acme/anna/intruder/"),
        display_name: None,
        description: None,
        color: None,
        sort_order: None,
        components: None,
        timezone_ics: None,
        schedule_transp: None,
        dead_properties: Vec::new(),
    };
    assert_eq!(
        kind_of(services.calendars.mkcalendar(&ben, foreign).await),
        ErrorKind::NotFound
    );

    let changes = davhaven_app::services::PropPatch {
        changes: vec![
            davhaven_app::services::PropertyChange::DisplayName(Some("Projekte".to_owned())),
            davhaven_app::services::PropertyChange::Description(Some("All projects".to_owned())),
        ],
    };
    let outcome = services.calendars.proppatch(&anna, &target, changes).await.unwrap();
    assert!(outcome.is_applied());
    let view = services.calendars.get_collection(&anna, &target).await.unwrap();
    let calendar = view.calendar.unwrap();
    assert_eq!(calendar.display_name, "Projekte");
    assert_eq!(calendar.description.as_deref(), Some("All projects"));

    let group_path = path("/dav/calendars/acme/ben/team-calendar/");
    services.calendars.list_home(&ben, &name("ben")).await.unwrap();
    let shared_property = davhaven_app::services::PropPatch {
        changes: vec![
            davhaven_app::services::PropertyChange::Color(Some("#ff0000".to_owned())),
            davhaven_app::services::PropertyChange::Timezone(Some("BEGIN:VTIMEZONE".to_owned())),
        ],
    };
    let outcome = services
        .calendars
        .proppatch(&ben, &group_path, shared_property)
        .await
        .unwrap();
    assert!(
        outcome.is_applied(),
        "members of a group have write access to its calendars"
    );

    services
        .calendars
        .delete_collection(&anna, &target, Conditions::none())
        .await
        .unwrap();
    assert_eq!(
        kind_of(services.calendars.get_collection(&anna, &target).await),
        ErrorKind::NotFound
    );
    services
        .calendars
        .delete_collection(&ben, &group_path, Conditions::none())
        .await
        .unwrap();
    let remaining = services.calendars.list_home(&ben, &name("ben")).await.unwrap();
    assert!(
        remaining.iter().all(|binding| binding.kind != CalendarKind::Group),
        "the binding is hidden"
    );
    let anna_home = services.calendars.list_home(&anna, &name("anna")).await.unwrap();
    assert!(
        anna_home.iter().any(|binding| binding.kind == CalendarKind::Group),
        "other members keep theirs"
    );
}

#[tokio::test]
async fn objects_keep_their_bytes_and_enforce_preconditions() {
    let services = AppServices::fake();
    let anna = login(&services, "anna@acme.example", seed::ANNA_PASSWORD).await;
    let standup = path("/dav/calendars/acme/anna/work/standup.ics");
    let view = services.objects.get(&anna, &standup).await.unwrap();
    assert_eq!(view.data.as_deref(), Some(seed::STANDUP_ICS));
    assert_eq!(view.etag, ETag::from_bytes(seed::STANDUP_ICS.as_bytes()));
    assert_eq!(view.uid.as_str(), "standup-1@acme.example");

    let body = lunch();
    let created = services
        .objects
        .put(&anna, put("/dav/calendars/acme/anna/work/lunch.ics", &body))
        .await
        .unwrap();
    assert!(created.created);
    assert_eq!(created.etag, Some(ETag::from_bytes(body.as_bytes())));
    let replaced = services
        .objects
        .put(&anna, put("/dav/calendars/acme/anna/work/lunch.ics", &body))
        .await
        .unwrap();
    assert!(!replaced.created);

    let mut create_only = put("/dav/calendars/acme/anna/work/lunch.ics", &body);
    create_only.preconditions = WritePrecondition::create_only();
    assert_eq!(
        kind_of(services.objects.put(&anna, create_only).await),
        ErrorKind::PreconditionFailed
    );
    let mut stale = put("/dav/calendars/acme/anna/work/lunch.ics", &body);
    stale.preconditions = WritePrecondition::if_match(ETag::from_bytes(b"something else"));
    assert_eq!(
        kind_of(services.objects.put(&anna, stale).await),
        ErrorKind::PreconditionFailed
    );

    let conflict = services
        .objects
        .put(&anna, put("/dav/calendars/acme/anna/work/duplicate.ics", &body))
        .await
        .err()
        .unwrap();
    assert_eq!(conflict.kind(), ErrorKind::Conflict);
    assert_eq!(
        conflict
            .precondition()
            .and_then(Precondition::href)
            .map(|href| href.as_str().to_owned()),
        Some("/dav/calendars/acme/anna/work/lunch.ics".to_owned())
    );
    let garbage = services
        .objects
        .put(
            &anna,
            put("/dav/calendars/acme/anna/work/garbage.ics", "not a calendar"),
        )
        .await
        .err()
        .unwrap();
    assert_eq!(garbage.kind(), ErrorKind::Invalid);
    assert_eq!(
        garbage.precondition().map(Precondition::code),
        Some("valid-calendar-data")
    );
    let oversized = "x".repeat(2 * 1024 * 1024);
    let too_large = services
        .objects
        .put(&anna, put("/dav/calendars/acme/anna/work/huge.ics", &oversized))
        .await
        .err()
        .unwrap();
    assert_eq!(too_large.kind(), ErrorKind::TooLarge);
}

#[tokio::test]
async fn sync_reports_changes_and_rejects_foreign_tokens() {
    let services = AppServices::fake();
    let anna = login(&services, "anna@acme.example", seed::ANNA_PASSWORD).await;
    let work = path("/dav/calendars/acme/anna/work/");
    services
        .objects
        .put(&anna, put("/dav/calendars/acme/anna/work/lunch.ics", &lunch()))
        .await
        .unwrap();
    let initial: SyncResult = services.objects.sync(&anna, &work, None, None).await.unwrap();
    assert_eq!(initial.changes.len(), 2);
    assert_eq!(initial.sync_token.seq, 2);
    services
        .objects
        .delete(
            &anna,
            DeleteRequest {
                path: path("/dav/calendars/acme/anna/work/lunch.ics"),
                preconditions: WritePrecondition::none(),
                schedule_reply: ScheduleReply::Send,
            },
        )
        .await
        .unwrap();
    let incremental = services
        .objects
        .sync(&anna, &work, Some(initial.sync_token), None)
        .await
        .unwrap();
    assert_eq!(incremental.changes.len(), 1);
    assert_eq!(incremental.changes[0].kind, davhaven_wire::ChangeKind::Delete);
    assert!(incremental.changes[0].etag.is_none());
    assert_eq!(incremental.sync_token.seq, 3);
    let caught_up = services
        .objects
        .sync(&anna, &work, Some(incremental.sync_token), None)
        .await
        .unwrap();
    assert_eq!(caught_up.changes.len(), 0);

    let future = SyncToken::new(initial.sync_token.collection, initial.sync_token.epoch, 99);
    let foreign = SyncToken::new(Uuid::from_u128(5), initial.sync_token.epoch, 1);
    for token in [future, foreign] {
        let error = services
            .objects
            .sync(&anna, &work, Some(token), None)
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), ErrorKind::Invalid);
        assert_eq!(error.precondition().map(Precondition::code), Some("valid-sync-token"));
    }
    let delete_again = services
        .objects
        .delete(
            &anna,
            DeleteRequest {
                path: path("/dav/calendars/acme/anna/work/lunch.ics"),
                preconditions: WritePrecondition::none(),
                schedule_reply: ScheduleReply::Send,
            },
        )
        .await;
    assert_eq!(kind_of::<DeleteOutcome>(delete_again), ErrorKind::NotFound);
}

#[tokio::test]
async fn objects_are_queried_moved_and_copied() {
    let services = AppServices::fake();
    let anna = login(&services, "anna@acme.example", seed::ANNA_PASSWORD).await;
    let work = path("/dav/calendars/acme/anna/work/");
    let entries = services
        .objects
        .multiget(
            &anna,
            &work,
            vec![
                path("/dav/calendars/acme/anna/work/standup.ics"),
                path("/dav/calendars/acme/anna/work/missing.ics"),
            ],
            CalendarDataSpec::metadata_only(),
        )
        .await
        .unwrap();
    assert!(matches!(&entries[0], MultigetEntry::Found(view) if view.data.is_none()));
    assert!(matches!(&entries[1], MultigetEntry::Missing(_)));
    let hits = services
        .objects
        .query(&anna, &work, ObjectFilter::default(), CalendarDataSpec::default())
        .await
        .unwrap();
    assert_eq!(hits.len(), 1);

    let moved = services
        .objects
        .move_to(
            &anna,
            MoveRequest {
                from: path("/dav/calendars/acme/anna/work/standup.ics"),
                to: path("/dav/calendars/acme/anna/work/daily.ics"),
                overwrite: false,
                preconditions: WritePrecondition::none(),
            },
        )
        .await
        .unwrap();
    assert!(moved.created);
    assert_eq!(
        kind_of(
            services
                .objects
                .get(&anna, &path("/dav/calendars/acme/anna/work/standup.ics"))
                .await
        ),
        ErrorKind::NotFound
    );
    let copy = |to: &str| CopyRequest {
        from: path("/dav/calendars/acme/anna/work/daily.ics"),
        to: path(to),
        overwrite: false,
    };
    let copied = services
        .objects
        .copy_to(&anna, copy("/dav/calendars/acme/anna/personal/daily.ics"))
        .await
        .unwrap();
    assert!(copied.created);
    let conflict = services
        .objects
        .copy_to(&anna, copy("/dav/calendars/acme/anna/work/again.ics"))
        .await
        .err()
        .unwrap();
    assert_eq!(conflict.precondition().map(Precondition::code), Some("no-uid-conflict"));
    assert_eq!(
        kind_of(
            services
                .objects
                .copy_to(&anna, copy("/dav/calendars/acme/anna/personal/daily.ics"))
                .await
        ),
        ErrorKind::PreconditionFailed,
        "an existing target needs Overwrite"
    );
}

#[tokio::test]
async fn permissions_and_tenants_are_isolated() {
    let app = FakeApp::standard();
    let services = app.services.clone();
    let ben = login(&services, "ben@acme.example", seed::BEN_PASSWORD).await;
    let gina = login(&services, "gina@globex.example", seed::GINA_PASSWORD).await;
    let standup = path("/dav/calendars/acme/anna/work/standup.ics");
    assert_eq!(kind_of(services.objects.get(&ben, &standup).await), ErrorKind::NotFound);
    assert_eq!(
        kind_of(services.objects.get(&gina, &standup).await),
        ErrorKind::NotFound
    );

    services.calendars.list_home(&ben, &name("ben")).await.unwrap();
    let shared = "/dav/calendars/acme/ben/team-calendar/meeting.ics";
    let body = lunch();
    services.objects.put(&ben, put(shared, &body)).await.unwrap();
    let anna = login(&services, "anna@acme.example", seed::ANNA_PASSWORD).await;
    services.calendars.list_home(&anna, &name("anna")).await.unwrap();
    let seen = services
        .objects
        .get(&anna, &path("/dav/calendars/acme/anna/team-calendar/meeting.ics"))
        .await
        .unwrap();
    assert_eq!(
        seen.etag,
        ETag::from_bytes(body.as_bytes()),
        "group members share one calendar"
    );

    app.state
        .write(|world| {
            let tenant = TenantSlug::parse(seed::TENANT).unwrap();
            let owner = world.principal_id(&tenant, &name("anna")).unwrap();
            world.add_calendar(
                owner,
                CalendarSlug::parse("managed").unwrap(),
                CalendarKind::Managed,
                "Managed",
            );
        })
        .await;
    let denied = services
        .objects
        .put(&anna, put("/dav/calendars/acme/anna/managed/x.ics", &lunch()))
        .await
        .err()
        .unwrap();
    assert_eq!(denied.kind(), ErrorKind::Forbidden);
    assert_eq!(denied.precondition().map(Precondition::code), Some("need-privileges"));
}

fn event(summary: &str, start: &str) -> EventView {
    serde_json::from_value(serde_json::json!({
        "summary": summary,
        "start": {"date_time": start, "time_zone": "Europe/Berlin"},
        "end": {"date_time": "2027-04-01T11:00:00", "time_zone": "Europe/Berlin"},
    }))
    .unwrap()
}

#[tokio::test]
async fn json_events_are_created_merged_listed_and_searched() {
    let services = AppServices::fake();
    let token = api(&services, seed::ANNA_TOKEN).await;
    let work = CalendarRef::Key {
        owner: name("anna"),
        slug: CalendarSlug::parse("work").unwrap(),
    };
    let key = ExternalKey::parse("crm-1").unwrap();
    let write = |view: EventView, if_match: Option<ETag>| EventWrite {
        target: Some(ObjectSelector::Key(key.clone())),
        event: view,
        notify_attendees: false,
        if_match,
        scope: ChangeScope::All,
    };
    let created = services
        .objects
        .put_event(&token, &work, write(event("Planning", "2027-04-01T10:00:00"), None))
        .await
        .unwrap();
    assert!(created.created);
    assert_eq!(created.event.external_key.as_ref(), Some(&key));
    let calendar_id = created.event.calendar_id.unwrap();
    assert_eq!(created.event.data.uid, Some(Uid::deterministic(calendar_id, &key)));
    assert_eq!(created.event.data.summary.as_deref(), Some("Planning"));
    let fetched = services.objects.get_by_key(&token, &work, &key).await.unwrap();
    assert_eq!(fetched.etag, created.event.etag);

    let stale = write(event("Planning", "2027-04-01T10:00:00"), Some(ETag::from_bytes(b"old")));
    assert_eq!(
        kind_of(services.objects.put_event(&token, &work, stale).await),
        ErrorKind::PreconditionFailed
    );
    let mut change = EventView::default();
    change.data.summary = Some("Planning (moved)".to_owned());
    let updated = services
        .objects
        .put_event(&token, &work, write(change, created.event.etag.clone()))
        .await
        .unwrap();
    assert!(!updated.created);
    assert_eq!(updated.event.data.summary.as_deref(), Some("Planning (moved)"));
    assert!(
        updated.event.data.start.is_some(),
        "fields that are not sent keep their value"
    );
    assert_ne!(updated.event.etag, created.event.etag);

    let page = services
        .objects
        .list(&token, &work, ObjectFilter::default(), PageRequest::first())
        .await
        .unwrap();
    assert_eq!(page.items.len(), 2);
    let changes = services.objects.changes(&token, &work, None, None).await.unwrap();
    assert_eq!(changes.changes.len(), 2);
    let found = services
        .objects
        .search_events(
            &token,
            EventSearch {
                text: Some("moved".to_owned()),
                ..EventSearch::default()
            },
            PageRequest::first(),
        )
        .await
        .unwrap();
    assert_eq!(found.items.len(), 1);
    let short = EventSearch {
        text: Some("x".to_owned()),
        ..EventSearch::default()
    };
    assert_eq!(
        kind_of(
            services
                .objects
                .search_events(&token, short, PageRequest::first())
                .await
        ),
        ErrorKind::Invalid
    );

    let admin = api(&services, seed::ADMIN_TOKEN).await;
    let forbidden = services
        .objects
        .put_event(&admin, &work, write(event("Nope", "2027-04-01T10:00:00"), None))
        .await;
    assert_eq!(
        kind_of(forbidden),
        ErrorKind::Forbidden,
        "tenant tokens never write events of user calendars"
    );
    services
        .objects
        .delete_by_key(&token, &work, &key, DeleteEventOptions::default())
        .await
        .unwrap();
    assert_eq!(
        kind_of(services.objects.get_by_key(&token, &work, &key).await),
        ErrorKind::NotFound
    );
}

#[tokio::test]
async fn batches_are_all_or_nothing_and_idempotent() {
    let services = AppServices::fake();
    let token = api(&services, seed::ANNA_TOKEN).await;
    let work = CalendarRef::Key {
        owner: name("anna"),
        slug: CalendarSlug::parse("work").unwrap(),
    };
    let key = |text: &str| ExternalKey::parse(text).unwrap();
    let valid_ical = lunch();
    let request = BatchRequest {
        items: vec![
            BatchItem {
                external_key: key("shop:1"),
                event: Some(event("Pickup", "2027-05-01T09:00:00")),
                ical: None,
            },
            BatchItem {
                external_key: key("shop:2"),
                event: None,
                ical: Some(valid_ical),
            },
        ],
        ..BatchRequest::default()
    };
    let first = services.objects.batch(&token, &work, request.clone()).await.unwrap();
    let outcomes: Vec<BatchOutcome> = first.results.iter().map(|result| result.outcome).collect();
    assert_eq!(outcomes, vec![BatchOutcome::Created, BatchOutcome::Created]);
    assert!(!first.has_failures());
    let second = services.objects.batch(&token, &work, request.clone()).await.unwrap();
    let outcomes: Vec<BatchOutcome> = second.results.iter().map(|result| result.outcome).collect();
    assert_eq!(outcomes, vec![BatchOutcome::Unchanged, BatchOutcome::Unchanged]);
    assert_eq!(
        second.sync_token, first.sync_token,
        "unchanged entries do not move the sync token"
    );

    let mut broken = request.clone();
    broken.items.push(BatchItem {
        external_key: key("shop:3"),
        event: None,
        ical: Some("not a calendar".to_owned()),
    });
    let failed = services.objects.batch(&token, &work, broken).await.unwrap();
    assert!(failed.has_failures());
    assert_eq!(failed.sync_token, first.sync_token, "nothing was written");
    let listed = services
        .objects
        .list(&token, &work, ObjectFilter::default(), PageRequest::first())
        .await
        .unwrap();
    assert_eq!(listed.items.len(), 3, "the standup plus the two batch objects");

    let replace = BatchRequest {
        mode: BatchMode::Replace,
        replace_scope_prefix: Some("shop:".to_owned()),
        items: vec![request.items[0].clone()],
        ..BatchRequest::default()
    };
    let replaced = services.objects.batch(&token, &work, replace).await.unwrap();
    let outcomes: Vec<BatchOutcome> = replaced.results.iter().map(|result| result.outcome).collect();
    assert_eq!(outcomes, vec![BatchOutcome::Unchanged, BatchOutcome::Deleted]);
    let invalid = BatchRequest::default();
    assert_eq!(
        kind_of(services.objects.batch(&token, &work, invalid).await),
        ErrorKind::Invalid
    );
}

#[tokio::test]
async fn services_the_fake_does_not_implement_answer_unsupported() {
    let services = AppServices::fake();
    let admin = api(&services, seed::ADMIN_TOKEN).await;
    let result = services.sharing.list_notifications(&admin, &name("anna")).await;
    assert_eq!(kind_of(result), ErrorKind::Unsupported);
    let result = services
        .tenants
        .get(&admin, &TenantSlug::parse(seed::TENANT).unwrap())
        .await;
    assert_eq!(kind_of(result), ErrorKind::Unsupported);
    let result = services.assets.get(&admin, "default", "page.css").await;
    assert_eq!(kind_of(result), ErrorKind::Unsupported);
}

#[tokio::test]
async fn the_recorder_answers_like_empty_services_and_keeps_every_call_in_order() {
    use davhaven_app::services::InboxEntry;
    use davhaven_app_fake::recorder::{Handed, Recorder};

    let mut services = AppServices::fake();
    let recorder = Recorder::install(&mut services);
    let anna = login(&services, "anna@acme.example", seed::ANNA_PASSWORD).await;
    let notification = path("/dav/calendars/acme/anna/notifications/n-1.xml");
    let inbox = path("/dav/calendars/acme/anna/inbox/");
    let item = path("/dav/calendars/acme/anna/inbox/i-1.ics");

    // Sharing and scheduling are the same recorder, which answers like services with nothing in them.
    let notifications = services.sharing.list_notifications(&anna, &name("anna")).await.unwrap();
    assert_eq!(notifications.len(), 0, "{notifications:?}");
    assert_eq!(
        kind_of(services.sharing.get_notification(&anna, &notification).await),
        ErrorKind::NotFound
    );
    let conditions = WritePrecondition {
        if_none_match_any: true,
        ..WritePrecondition::none()
    };
    services
        .sharing
        .delete_notification_if(&anna, &notification, conditions.clone())
        .await
        .unwrap();
    let entries = services
        .scheduling
        .inbox_get_many(&anna, &inbox, vec![item.clone()], &CalendarDataSpec::metadata_only())
        .await
        .unwrap();
    assert!(
        matches!(entries.as_slice(), [InboxEntry::Missing(missing)] if *missing == item),
        "{entries:?}"
    );
    services
        .scheduling
        .outbox_post(&anna, &name("anna"), "BEGIN:VCALENDAR".to_owned())
        .await
        .unwrap();
    // What the fake has no answer for is not recorded: it is no call a layer hands on.
    assert_eq!(
        kind_of(services.scheduling.rsvp_page(&anna).await),
        ErrorKind::Unsupported
    );

    assert_eq!(
        recorder.calls(),
        vec![
            Handed::ListNotifications(name("anna")),
            Handed::GetNotification(notification.clone()),
            Handed::DeleteNotification {
                path: notification,
                conditions,
            },
            Handed::InboxGetMany {
                inbox,
                paths: vec![item],
                spec: CalendarDataSpec::metadata_only(),
            },
            Handed::OutboxPost {
                owner: name("anna"),
                body: "BEGIN:VCALENDAR".to_owned(),
            },
        ]
    );
    recorder.clear();
    assert_eq!(recorder.calls(), Vec::<Handed>::new());
}

fn dead(namespace: &str, local: &str, value: Option<&str>) -> davhaven_app::services::PropertyChange {
    davhaven_app::services::PropertyChange::Dead {
        name: davhaven_app::services::PropertyName {
            namespace: namespace.to_owned(),
            local: local.to_owned(),
        },
        value_xml: value.map(str::to_owned),
    }
}

fn patch_of(changes: Vec<davhaven_app::services::PropertyChange>) -> davhaven_app::services::PropPatch {
    davhaven_app::services::PropPatch { changes }
}

#[tokio::test]
async fn dead_properties_belong_to_the_binding_they_were_set_through() {
    use davhaven_app::services::PropertyStatus;
    let services = AppServices::fake();
    let anna = login(&services, "anna@acme.example", seed::ANNA_PASSWORD).await;
    let ben = login(&services, "ben@acme.example", seed::BEN_PASSWORD).await;
    // Both are members of `team`: each lists the home once and has a binding of the group calendar of their own.
    services.calendars.list_home(&anna, &name("anna")).await.unwrap();
    services.calendars.list_home(&ben, &name("ben")).await.unwrap();
    let annas = path("/dav/calendars/acme/anna/team-calendar/");
    let bens = path("/dav/calendars/acme/ben/team-calendar/");
    let note = |who: &str| format!("<x:note xmlns:x=\"urn:example:x\">{who}</x:note>");
    let properties = |view: davhaven_app::services::CollectionView| -> Vec<(String, String)> {
        view.dead_properties
            .into_iter()
            .map(|property| (property.name.local, property.value_xml))
            .collect()
    };

    let outcome = services
        .calendars
        .proppatch(
            &anna,
            &annas,
            patch_of(vec![dead("urn:example:x", "note", Some(&note("anna")))]),
        )
        .await
        .unwrap();
    assert!(outcome.is_applied());
    assert_eq!(
        properties(services.calendars.get_collection(&anna, &annas).await.unwrap()),
        vec![("note".to_owned(), note("anna"))]
    );
    assert!(
        properties(services.calendars.get_collection(&ben, &bens).await.unwrap()).is_empty(),
        "what one member keeps on a calendar is not shown to the others"
    );

    // The same name on the other binding is another property; removing one leaves the other.
    let outcome = services
        .calendars
        .proppatch(
            &ben,
            &bens,
            patch_of(vec![dead("urn:example:x", "note", Some(&note("ben")))]),
        )
        .await
        .unwrap();
    assert_eq!(outcome.results[0].status, PropertyStatus::Applied);
    let outcome = services
        .calendars
        .proppatch(&anna, &annas, patch_of(vec![dead("urn:example:x", "note", None)]))
        .await
        .unwrap();
    assert!(outcome.is_applied());
    assert_eq!(
        properties(services.calendars.get_collection(&anna, &annas).await.unwrap()),
        Vec::<(String, String)>::new(),
        "the property of anna is gone"
    );
    assert_eq!(
        properties(services.calendars.get_collection(&ben, &bens).await.unwrap()),
        vec![("note".to_owned(), note("ben"))]
    );
}

#[tokio::test]
async fn the_limits_of_the_world_are_the_ones_the_fake_enforces() {
    use davhaven_app::services::PropertyStatus;
    let defaults = FakeApp::standard();
    assert_eq!(defaults.services.limits.dav.max_dead_properties, 50, "PLAN 2.15");

    let mut limits = davhaven_domain::Limits::default();
    limits.dav.max_dead_properties = 2;
    limits.dav.max_dead_property_size = 40;
    limits.ical.max_resource_size = 200;
    let mut world = seed::standard_world();
    world.set_limits(limits);
    let services = FakeApp::new(world).services;
    assert_eq!(
        services.limits.dav.max_dead_properties, 2,
        "the services carry the limits of the world"
    );
    let anna = login(&services, "anna@acme.example", seed::ANNA_PASSWORD).await;
    let work = path("/dav/calendars/acme/anna/work/");

    // The count is per binding, and a property that is replaced is not a new one.
    for local in ["a", "b"] {
        let outcome = services
            .calendars
            .proppatch(&anna, &work, patch_of(vec![dead("urn:x", local, Some("v"))]))
            .await
            .unwrap();
        assert!(outcome.is_applied(), "{local}");
    }
    let third = services
        .calendars
        .proppatch(&anna, &work, patch_of(vec![dead("urn:x", "c", Some("v"))]))
        .await
        .unwrap();
    assert_eq!(third.results[0].status, PropertyStatus::InsufficientStorage);
    let replaced = services
        .calendars
        .proppatch(&anna, &work, patch_of(vec![dead("urn:x", "a", Some("w"))]))
        .await
        .unwrap();
    assert!(replaced.is_applied());

    // The size counts the namespace and the name as well as the value, like the real application: 5 + 1 + 35 is over 40,
    // and the same value under a shorter name would not be.
    let long = "v".repeat(35);
    let too_big = services
        .calendars
        .proppatch(&anna, &work, patch_of(vec![dead("urn:x", "a", Some(&long))]))
        .await
        .unwrap();
    assert_eq!(too_big.results[0].status, PropertyStatus::InsufficientStorage);
    let fits = services
        .calendars
        .proppatch(&anna, &work, patch_of(vec![dead("urn:x", "a", Some(&"v".repeat(34)))]))
        .await
        .unwrap();
    assert!(fits.is_applied());

    // An object may not be larger than `limits.ical.max_resource_size`.
    let refused = services
        .objects
        .put(&anna, put("/dav/calendars/acme/anna/work/lunch.ics", &lunch()))
        .await;
    assert_eq!(kind_of(refused), ErrorKind::TooLarge);
    assert!(lunch().len() > 200);
    let default_services = defaults.services;
    let anna = login(&default_services, "anna@acme.example", seed::ANNA_PASSWORD).await;
    default_services
        .objects
        .put(&anna, put("/dav/calendars/acme/anna/work/lunch.ics", &lunch()))
        .await
        .unwrap();
}

/// A MKCALENDAR of `target` that sets `properties` (namespace, name, value).
fn mkcalendar_with(target: &str, properties: &[(&str, &str, &str)]) -> davhaven_app::services::MkCalendar {
    davhaven_app::services::MkCalendar {
        path: path(target),
        display_name: None,
        description: None,
        color: None,
        sort_order: None,
        components: None,
        timezone_ics: None,
        schedule_transp: None,
        dead_properties: properties
            .iter()
            .map(|(namespace, local, value)| davhaven_app::services::DeadProperty {
                name: davhaven_app::services::PropertyName {
                    namespace: (*namespace).to_owned(),
                    local: (*local).to_owned(),
                },
                value_xml: (*value).to_owned(),
            })
            .collect(),
    }
}

#[tokio::test]
async fn mkcalendar_enforces_the_limits_of_the_world_before_it_asks_who_may_make_the_calendar() {
    let mut limits = davhaven_domain::Limits::default();
    limits.dav.max_dead_properties = 2;
    limits.dav.max_dead_property_size = 40;
    let mut world = seed::standard_world();
    world.set_limits(limits);
    let services = FakeApp::new(world).services;
    let anna = login(&services, "anna@acme.example", seed::ANNA_PASSWORD).await;
    let ben = login(&services, "ben@acme.example", seed::BEN_PASSWORD).await;

    // Too many properties, and one that is too large (5 + 1 + 35 is over 40): refused, and the calendar is not made.
    let long = "v".repeat(35);
    for (slug, properties) in [
        (
            "three",
            vec![("urn:x", "a", "1"), ("urn:x", "b", "2"), ("urn:x", "c", "3")],
        ),
        ("big", vec![("urn:x", "a", long.as_str())]),
    ] {
        let target = format!("/dav/calendars/acme/anna/{slug}/");
        assert_eq!(
            kind_of(
                services
                    .calendars
                    .mkcalendar(&anna, mkcalendar_with(&target, &properties))
                    .await
            ),
            ErrorKind::Invalid,
            "{slug}"
        );
        assert_eq!(
            kind_of(services.calendars.get_collection(&anna, &path(&target)).await),
            ErrorKind::NotFound,
            "{slug}: nothing was made"
        );
    }

    // The application judges the request before it asks whether the caller may make it, and so does the fake: a request that is
    // too large and not allowed (ben in the home of anna) is the first, where a smaller one would be hidden.
    let foreign = "/dav/calendars/acme/anna/intruder/";
    assert_eq!(
        kind_of(
            services
                .calendars
                .mkcalendar(
                    &ben,
                    mkcalendar_with(
                        foreign,
                        &[("urn:x", "a", "1"), ("urn:x", "b", "2"), ("urn:x", "c", "3")]
                    )
                )
                .await
        ),
        ErrorKind::Invalid
    );
    assert_eq!(
        kind_of(
            services
                .calendars
                .mkcalendar(&ben, mkcalendar_with(foreign, &[("urn:x", "a", "1")]))
                .await
        ),
        ErrorKind::NotFound
    );

    // Within the limits the properties are kept, on the binding of the creator.
    let target = "/dav/calendars/acme/anna/two/";
    services
        .calendars
        .mkcalendar(
            &anna,
            mkcalendar_with(target, &[("urn:x", "a", "1"), ("urn:x", "b", "2")]),
        )
        .await
        .unwrap();
    let view = services.calendars.get_collection(&anna, &path(target)).await.unwrap();
    let mut kept: Vec<(String, String)> = view
        .dead_properties
        .into_iter()
        .map(|property| (property.name.local, property.value_xml))
        .collect();
    kept.sort();
    assert_eq!(
        kept,
        vec![("a".to_owned(), "1".to_owned()), ("b".to_owned(), "2".to_owned())]
    );
}
