//! Principals: provisioning semantics, memberships, deletion, search, DAV properties and address classification.

use davhaven_testkit::davhaven_app::services::{
    AddressClass, Conditions, DeleteOptions, MergePatch, PageRequest, PrincipalFilter, PrincipalSearch, PrincipalSpec,
};
use davhaven_testkit::davhaven_domain::{
    CalendarKind, CalendarUserAddress, Email, ErrorKind, EventType, Locale, PrincipalKind, PrincipalName,
    PrincipalStatus, ResourcePath, Scope, ScopeSet,
};
use davhaven_testkit::davhaven_wire::{AppPasswordCreate, PrincipalWrite};
use serde_json::json;

use super::support::{World, principal_body};

fn address(text: &str) -> CalendarUserAddress {
    CalendarUserAddress::parse(text).unwrap()
}

fn name(text: &str) -> PrincipalName {
    PrincipalName::parse(text).unwrap()
}

#[tokio::test]
async fn a_new_user_gets_a_personal_calendar_and_the_events_and_audit_records_of_its_creation() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;

    let calendars = world
        .services
        .calendars
        .list_owned(&world.admin(&acme), &anna.name, PageRequest::first())
        .await
        .unwrap();
    assert_eq!(calendars.items.len(), 1);
    let personal = &calendars.items[0];
    assert_eq!(personal.slug.as_str(), "personal");
    assert_eq!(personal.kind, CalendarKind::Personal);
    assert_eq!(personal.display_name, "Personal");
    assert!(
        personal
            .dav_url
            .as_str()
            .ends_with("/dav/calendars/acme/anna/personal/"),
        "{}",
        personal.dav_url
    );

    let events: Vec<EventType> = world.events(&acme).await.iter().map(|event| event.event_type).collect();
    assert_eq!(events, vec![EventType::PrincipalCreated, EventType::CalendarCreated]);
    assert_eq!(
        world.audit_actions(&acme).await,
        vec!["tenant.created", "principal.created"]
    );

    // Groups and resources get no personal calendar; the tenant can switch it off; German tenants get a German name.
    let team = world.group(&acme, "team", &[&anna]).await;
    let room = world.principal(&acme, "room-1", PrincipalKind::Resource).await;
    for owner in [&team, &room] {
        let calendars = world
            .services
            .calendars
            .list_owned(&world.admin(&acme), &owner.name, PageRequest::first())
            .await
            .unwrap();
        assert!(calendars.items.is_empty(), "{}", owner.name);
    }
    let quiet = world
        .org_with("quiet", |settings| settings.auto_create_personal_calendar = false)
        .await;
    let ben = world.user(&quiet, "ben").await;
    let none = world
        .services
        .calendars
        .list_owned(&world.admin(&quiet), &ben.name, PageRequest::first())
        .await
        .unwrap();
    assert!(none.items.is_empty());
    let mut body = principal_body(&acme, "clara", PrincipalKind::User);
    body.locale = Some(Locale::de());
    world.principal_write(&acme, "clara", body).await.unwrap();
    let calendars = world
        .services
        .calendars
        .list_owned(&world.admin(&acme), &name("clara"), PageRequest::first())
        .await
        .unwrap();
    assert_eq!(calendars.items[0].display_name, "Persönlich");
}

#[tokio::test]
async fn the_same_body_twice_changes_nothing_and_a_replace_clears_what_the_body_leaves_out() {
    let world = World::new();
    let acme = world.org("acme").await;
    let mut body = principal_body(&acme, "anna", PrincipalKind::User);
    body.external_ref = Some("hr-17".to_owned());
    body.addresses = vec![address("mailto:anna.schmidt@elsewhere.example")];
    let first = world.principal_write(&acme, "anna", body.clone()).await.unwrap();
    assert_eq!(first.version, 1);
    assert_eq!(first.addresses, vec![address("mailto:anna.schmidt@elsewhere.example")]);
    let events = world.events(&acme).await.len();
    let audits = world.audit(&acme).await.len();

    world.clock.advance(chrono::Duration::hours(1));
    let again = world.principal_write(&acme, "anna", body).await.unwrap();
    assert_eq!(again, first, "the same body: same version, same timestamp");
    assert_eq!(world.events(&acme).await.len(), events, "no event for a no-op");
    assert_eq!(world.audit(&acme).await.len(), audits, "no audit record for a no-op");

    let replaced = world
        .principal_write(&acme, "anna", principal_body(&acme, "anna", PrincipalKind::User))
        .await
        .unwrap();
    assert_eq!(replaced.version, 2);
    assert_eq!(
        replaced.external_ref, None,
        "PUT replaces: what the body leaves out is cleared"
    );
    assert!(replaced.addresses.is_empty());
    assert_eq!(
        world.audit_actions(&acme).await.last().map(String::as_str),
        Some("principal.updated")
    );
    let last = world.events(&acme).await.last().unwrap().event_type;
    assert_eq!(last, EventType::PrincipalUpdated);

    // A merge patch changes one member and keeps the rest.
    let patched = world
        .services
        .principals
        .patch(
            &world.admin(&acme),
            &name("anna"),
            MergePatch::new(json!({"display_name": "Anna S.", "timezone": "Europe/Berlin"})).unwrap(),
            Conditions::if_match(2),
        )
        .await
        .unwrap();
    assert_eq!(patched.display_name, "Anna S.");
    assert_eq!(
        patched.timezone.map(|zone| zone.to_string()),
        Some("Europe/Berlin".to_owned())
    );
    assert_eq!(patched.email.as_ref().map(Email::as_str), Some("anna@acme.example"));
    assert_eq!(patched.version, 3);
    let stale = world
        .services
        .principals
        .patch(
            &world.admin(&acme),
            &name("anna"),
            MergePatch::new(json!({"display_name": "Late"})).unwrap(),
            Conditions::if_match(2),
        )
        .await
        .unwrap_err();
    assert_eq!(stale.kind(), ErrorKind::PreconditionFailed);
    let unknown = world
        .services
        .principals
        .patch(
            &world.admin(&acme),
            &name("ghost"),
            MergePatch::new(json!({"display_name": "x"})).unwrap(),
            Conditions::none(),
        )
        .await
        .unwrap_err();
    assert_eq!(unknown.kind(), ErrorKind::NotFound);
}

#[tokio::test]
async fn bodies_are_validated_before_anything_is_stored() {
    let world = World::new();
    let acme = world.org("acme").await;
    let blank = {
        let mut body = principal_body(&acme, "anna", PrincipalKind::User);
        body.display_name = "  ".to_owned();
        body
    };
    let error = world.principal_write(&acme, "anna", blank).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Invalid);
    assert_eq!(
        error.field_errors().first().map(|field| field.pointer),
        Some("/display_name")
    );

    let deleted_status = {
        let mut body = principal_body(&acme, "anna", PrincipalKind::User);
        body.status = Some(PrincipalStatus::Deleted);
        body
    };
    let error = world.principal_write(&acme, "anna", deleted_status).await.unwrap_err();
    assert_eq!(error.field_errors().first().map(|field| field.pointer), Some("/status"));

    let urn = {
        let mut body = principal_body(&acme, "anna", PrincipalKind::User);
        body.addresses = vec![address("urn:uuid:00000000-0000-0000-0000-000000000001")];
        body
    };
    let error = world.principal_write(&acme, "anna", urn).await.unwrap_err();
    assert_eq!(
        error.field_errors().first().map(|field| field.pointer),
        Some("/addresses")
    );

    let error = world
        .services
        .principals
        .get(&world.admin(&acme), &name("anna"))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound, "nothing was created");

    // The kind of a principal never changes.
    world.user(&acme, "anna").await;
    let as_group = principal_body(&acme, "anna", PrincipalKind::Group);
    let error = world.principal_write(&acme, "anna", as_group).await.unwrap_err();
    assert_eq!(error.field_errors().first().map(|field| field.pointer), Some("/kind"));
}

#[tokio::test]
async fn names_addresses_and_external_references_are_unique_within_a_tenant_only() {
    let world = World::new();
    let acme = world.org("acme").await;
    let other = world.org("other").await;
    world.user(&acme, "anna").await;

    // The same address in other letter case belongs to anna already.
    let mut clash = principal_body(&acme, "ben", PrincipalKind::User);
    clash.email = Some(Email::parse("ANNA@acme.example").unwrap());
    let error = world.principal_write(&acme, "ben", clash).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
    let mut further = principal_body(&acme, "ben", PrincipalKind::User);
    further.addresses = vec![address("mailto:anna@acme.example")];
    assert_eq!(
        world.principal_write(&acme, "ben", further).await.unwrap_err().kind(),
        ErrorKind::Conflict
    );

    let mut first = principal_body(&acme, "carla", PrincipalKind::User);
    first.external_ref = Some("hr-1".to_owned());
    world.principal_write(&acme, "carla", first).await.unwrap();
    let mut second = principal_body(&acme, "dora", PrincipalKind::User);
    second.external_ref = Some("hr-1".to_owned());
    assert_eq!(
        world.principal_write(&acme, "dora", second).await.unwrap_err().kind(),
        ErrorKind::Conflict
    );

    // Another tenant has its own name space and its own addresses.
    let mut elsewhere = principal_body(&other, "anna", PrincipalKind::User);
    elsewhere.email = Some(Email::parse("anna@acme.example").unwrap());
    world.principal_write(&other, "anna", elsewhere).await.unwrap();
}

#[tokio::test]
async fn deleting_a_principal_hides_it_and_revokes_what_it_could_be_used_for() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let team = world.group(&acme, "team", &[&anna, &ben]).await;
    let admin = world.admin(&acme);
    let password = world
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
    let generation_before = world
        .read(&acme)
        .await
        .principals()
        .get(anna.id)
        .await
        .unwrap()
        .credential_generation;
    let current = world.services.principals.get(&admin, &anna.name).await.unwrap();

    let required = world
        .services
        .principals
        .delete(&admin, &anna.name, DeleteOptions::default())
        .await
        .unwrap_err();
    assert_eq!(required.kind(), ErrorKind::PreconditionRequired);
    let stale = DeleteOptions {
        conditions: Conditions::if_match(current.version + 1),
        ..DeleteOptions::default()
    };
    assert_eq!(
        world
            .services
            .principals
            .delete(&admin, &anna.name, stale)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PreconditionFailed
    );
    let reader = world.tenant_token(&acme, ScopeSet::of(&[Scope::PrincipalsRead]));
    let options = DeleteOptions {
        conditions: Conditions::if_match(current.version),
        ..DeleteOptions::default()
    };
    assert_eq!(
        world
            .services
            .principals
            .delete(&reader, &anna.name, options)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );

    world
        .services
        .principals
        .delete(&admin, &anna.name, options)
        .await
        .unwrap();

    // Hidden at once: not readable, not listed, not a group member.
    assert_eq!(
        world
            .services
            .principals
            .get(&admin, &anna.name)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    let listed = world
        .services
        .principals
        .list(&admin, PrincipalFilter::default(), PageRequest::first())
        .await
        .unwrap();
    assert!(listed.items.iter().all(|view| view.name != anna.name));
    let members = world.services.principals.members(&admin, &team.name).await.unwrap();
    assert_eq!(members.members, vec![ben.name.clone()]);

    // Revoked: the app password, with a new credential generation so cached verifications end.
    let mut tx = world.read(&acme).await;
    let stored = tx.credentials().get_app_password(password.id).await.unwrap();
    assert!(stored.revoked_at.is_some());
    let row = tx.principals().get(anna.id).await.unwrap();
    assert_eq!(row.status, PrincipalStatus::Deleted);
    assert!(row.deleted_at.is_some());
    assert!(row.credential_generation > generation_before);
    drop(tx);

    // The name and the addresses stay reserved until the purge.
    let reuse = principal_body(&acme, "anna", PrincipalKind::User);
    assert_eq!(
        world.principal_write(&acme, "anna", reuse).await.unwrap_err().kind(),
        ErrorKind::Conflict
    );
    let mut address_only = principal_body(&acme, "annette", PrincipalKind::User);
    address_only.email = Some(Email::parse("anna@acme.example").unwrap());
    assert_eq!(
        world
            .principal_write(&acme, "annette", address_only)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Conflict
    );
    let actions = world.audit_actions(&acme).await;
    assert!(actions.contains(&"principal.deleted".to_owned()), "{actions:?}");
    assert!(!actions.contains(&"principal.purged".to_owned()));
    assert_eq!(world.events_of(&acme, EventType::PrincipalDeleted).await.len(), 1);
}

#[tokio::test]
async fn a_purge_removes_the_principal_for_good_and_frees_its_name() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let admin = world.admin(&acme);
    let current = world.services.principals.get(&admin, &anna.name).await.unwrap();
    world
        .services
        .principals
        .delete(
            &admin,
            &anna.name,
            DeleteOptions {
                purge: true,
                conditions: Conditions::if_match(current.version),
                ..DeleteOptions::default()
            },
        )
        .await
        .unwrap();
    let mut tx = world.read(&acme).await;
    assert!(tx.principals().get(anna.id).await.is_err(), "the row is gone");
    assert!(
        tx.calendars().list_owned(anna.id).await.unwrap().is_empty(),
        "owned calendars went with it"
    );
    drop(tx);
    let actions = world.audit_actions(&acme).await;
    assert!(actions.contains(&"principal.purged".to_owned()), "{actions:?}");
    // Free again.
    let again = world.user(&acme, "anna").await;
    assert_ne!(again.id, anna.id);
}

#[tokio::test]
async fn groups_hold_users_resources_and_services_and_membership_changes_are_events_of_the_difference() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let carla = world.user(&acme, "carla").await;
    let admin = world.admin(&acme);
    let team = world.principal(&acme, "team", PrincipalKind::Group).await;
    let other_group = world.principal(&acme, "other", PrincipalKind::Group).await;

    let set = world
        .services
        .principals
        .set_members(
            &admin,
            &team.name,
            vec![ben.name.clone(), anna.name.clone(), anna.name.clone()],
        )
        .await
        .unwrap();
    assert_eq!(
        set.members,
        vec![anna.name.clone(), ben.name.clone()],
        "sorted, without duplicates"
    );
    let changed = world.events_of(&acme, EventType::MembershipChanged).await;
    assert_eq!(changed.len(), 1);

    // The same set again changes nothing and says nothing.
    world
        .services
        .principals
        .set_members(&admin, &team.name, vec![anna.name.clone(), ben.name.clone()])
        .await
        .unwrap();
    assert_eq!(world.events_of(&acme, EventType::MembershipChanged).await.len(), 1);

    // Adding an existing member and removing a non-member are quiet; real changes are events.
    world
        .services
        .principals
        .add_member(&admin, &team.name, &anna.name)
        .await
        .unwrap();
    world
        .services
        .principals
        .remove_member(&admin, &team.name, &carla.name)
        .await
        .unwrap();
    assert_eq!(world.events_of(&acme, EventType::MembershipChanged).await.len(), 1);
    world
        .services
        .principals
        .add_member(&admin, &team.name, &carla.name)
        .await
        .unwrap();
    world
        .services
        .principals
        .remove_member(&admin, &team.name, &anna.name)
        .await
        .unwrap();
    assert_eq!(world.events_of(&acme, EventType::MembershipChanged).await.len(), 3);
    let members = world.services.principals.members(&admin, &team.name).await.unwrap();
    assert_eq!(members.members, vec![ben.name.clone(), carla.name.clone()]);

    // Unknown members and groups as members are invalid; users are no groups.
    let unknown = world
        .services
        .principals
        .set_members(&admin, &team.name, vec![name("ghost")])
        .await
        .unwrap_err();
    assert_eq!(unknown.kind(), ErrorKind::Invalid);
    assert_eq!(
        unknown.field_errors().first().map(|field| field.code),
        Some("unknown-member")
    );
    let nested = world
        .services
        .principals
        .set_members(&admin, &team.name, vec![other_group.name.clone()])
        .await
        .unwrap_err();
    assert_eq!(
        nested.field_errors().first().map(|field| field.code),
        Some("group-member")
    );
    let not_a_group = world.services.principals.members(&admin, &anna.name).await.unwrap_err();
    assert_eq!(not_a_group.kind(), ErrorKind::Invalid);
    let missing = world
        .services
        .principals
        .members(&admin, &name("ghost"))
        .await
        .unwrap_err();
    assert_eq!(missing.kind(), ErrorKind::NotFound);
    assert_eq!(
        world
            .services
            .principals
            .members(&admin, &team.name)
            .await
            .unwrap()
            .members
            .len(),
        2,
        "a refused change changed nothing"
    );
}

#[tokio::test]
async fn principals_are_searched_by_name_display_name_and_address_within_the_tenant() {
    let world = World::new();
    let acme = world.org("acme").await;
    let other = world.org("other").await;
    let anna = world.user(&acme, "anna").await;
    let mut ben_body = principal_body(&acme, "ben", PrincipalKind::User);
    ben_body.display_name = "Benedikt Annaberg".to_owned();
    world.principal_write(&acme, "ben", ben_body).await.unwrap();
    world.user(&acme, "carla").await;
    world.user(&other, "annabelle").await;
    let dav = world.dav(&acme, &anna);

    let hits = world
        .services
        .principals
        .search(&dav, PrincipalSearch::new("ANNA"))
        .await
        .unwrap();
    let mut names: Vec<&str> = hits.iter().map(|hit| hit.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        vec!["anna", "ben"],
        "by name and display name, case-insensitively, own tenant only"
    );
    let anna_hit = hits.iter().find(|hit| hit.name.as_str() == "anna").unwrap();
    assert!(anna_hit.addresses.contains(&address("mailto:anna@acme.example")));
    assert!(anna_hit.path.format().ends_with("/principals/acme/anna/"));

    let by_address = world
        .services
        .principals
        .search(&dav, PrincipalSearch::new("carla@acme").limited(1))
        .await
        .unwrap();
    assert_eq!(by_address.len(), 1);
    assert_eq!(by_address[0].name.as_str(), "carla");

    let error = world
        .services
        .principals
        .search(&dav, PrincipalSearch::new(" a "))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Invalid);
    assert_eq!(error.field_errors().first().map(|field| field.code), Some("too-short"));

    // Deleted principals are not found; feed readers and system tokens may not search at all.
    let admin = world.admin(&acme);
    let ben = world.services.principals.get(&admin, &name("ben")).await.unwrap();
    world
        .services
        .principals
        .delete(
            &admin,
            &name("ben"),
            DeleteOptions {
                conditions: Conditions::if_match(ben.version),
                ..DeleteOptions::default()
            },
        )
        .await
        .unwrap();
    let hits = world
        .services
        .principals
        .search(&dav, PrincipalSearch::new("anna"))
        .await
        .unwrap();
    assert_eq!(hits.len(), 1);
    let feed = world.feed(&acme, &anna, world.token_id());
    assert_eq!(
        world
            .services
            .principals
            .search(&feed, PrincipalSearch::new("anna"))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );
}

#[tokio::test]
async fn dav_properties_list_the_addresses_the_collections_and_the_groups() {
    let world = World::new();
    let acme = world
        .org_with("acme", |settings| settings.login_address_is_cua = true)
        .await;
    let other = world.org("other").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let team = world.group(&acme, "team", &[&anna, &ben]).await;
    let dav = world.dav(&acme, &ben);
    let principal_path = |who: &super::support::Person| ResourcePath::Principal {
        tenant: acme.slug.clone(),
        principal: who.name.clone(),
    };

    let props = world
        .services
        .principals
        .dav_properties(&dav, &principal_path(&anna))
        .await
        .unwrap();
    assert_eq!(props.name, anna.name);
    assert_eq!(props.id, anna.id);
    let addresses: Vec<String> = props
        .addresses
        .iter()
        .map(|address| address.as_str().to_owned())
        .collect();
    assert_eq!(
        addresses,
        vec![
            "mailto:anna@acme.example".to_owned(),
            "/dav/principals/acme/anna/".to_owned(),
            format!("urn:uuid:{}", anna.id),
        ],
        "the primary address, the principal URL and the urn:uuid; the login address equals the primary one here"
    );
    assert_eq!(props.home.format(), "/dav/calendars/acme/anna/");
    assert_eq!(props.inbox.format(), "/dav/calendars/acme/anna/inbox/");
    assert_eq!(props.outbox.format(), "/dav/calendars/acme/anna/outbox/");
    assert_eq!(props.notifications.format(), "/dav/calendars/acme/anna/notifications/");
    assert_eq!(props.group_membership, vec![principal_path(&team)]);
    assert!(props.group_members.is_empty());

    let group = world
        .services
        .principals
        .dav_properties(&dav, &principal_path(&team))
        .await
        .unwrap();
    assert_eq!(group.group_members, vec![principal_path(&anna), principal_path(&ben)]);

    // Other tenants' principals and unknown ones do not exist.
    let foreign = ResourcePath::Principal {
        tenant: other.slug.clone(),
        principal: anna.name.clone(),
    };
    assert_eq!(
        world
            .services
            .principals
            .dav_properties(&dav, &foreign)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        world
            .services
            .principals
            .dav_properties(
                &dav,
                &principal_path(&super::support::Person {
                    id: anna.id,
                    name: name("ghost")
                })
            )
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        world
            .services
            .principals
            .dav_properties(&dav, &world.home(&acme, &anna))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound,
        "only principal resources have principal properties"
    );
}

#[tokio::test]
async fn the_login_address_counts_as_a_calendar_user_address_only_when_the_tenant_says_so() {
    let world = World::new();
    let plain = world.org("plain").await;
    let cua = world
        .org_with("cua", |settings| settings.login_address_is_cua = true)
        .await;
    let mut body = principal_body(&plain, "anna", PrincipalKind::User);
    body.email = Some(Email::parse("anna@mail.elsewhere.example").unwrap());
    world.principal_write(&plain, "anna", body.clone()).await.unwrap();
    let mut body = principal_body(&cua, "anna", PrincipalKind::User);
    body.email = Some(Email::parse("anna@mail.elsewhere.example").unwrap());
    world.principal_write(&cua, "anna", body).await.unwrap();
    let anna_plain = super::support::Person {
        id: world
            .services
            .principals
            .get(&world.admin(&plain), &name("anna"))
            .await
            .unwrap()
            .id,
        name: name("anna"),
    };
    let anna_cua = super::support::Person {
        id: world
            .services
            .principals
            .get(&world.admin(&cua), &name("anna"))
            .await
            .unwrap()
            .id,
        name: name("anna"),
    };

    let login = address("mailto:anna@plain.example");
    let class = world
        .services
        .principals
        .resolve_address(&world.dav(&plain, &anna_plain), &login)
        .await
        .unwrap();
    assert_eq!(
        class,
        AddressClass::External,
        "not an address of anna unless the tenant counts it"
    );
    let login = address("mailto:anna@cua.example");
    let class = world
        .services
        .principals
        .resolve_address(&world.dav(&cua, &anna_cua), &login)
        .await
        .unwrap();
    assert_eq!(
        class,
        AddressClass::Internal {
            principal: anna_cua.id,
            name: anna_cua.name.clone(),
            kind: PrincipalKind::User
        }
    );
}

#[tokio::test]
async fn addresses_are_classified_for_scheduling() {
    let world = World::new();
    let acme = world.org("acme").await;
    let other = world.org("other").await;
    let anna = world.user(&acme, "anna").await;
    world.user(&other, "olga").await;
    let team = world.group(&acme, "team", &[&anna]).await;
    let dav = world.dav(&acme, &anna);

    let internal = |who: &super::support::Person, kind| AddressClass::Internal {
        principal: who.id,
        name: who.name.clone(),
        kind,
    };
    let classify = |text: String| {
        let world = &world;
        let dav = &dav;
        async move {
            world
                .services
                .principals
                .resolve_address(dav, &address(&text))
                .await
                .unwrap()
        }
    };
    assert_eq!(
        classify("mailto:Anna@ACME.example".to_owned()).await,
        internal(&anna, PrincipalKind::User)
    );
    assert_eq!(
        classify(format!("urn:uuid:{}", anna.id)).await,
        internal(&anna, PrincipalKind::User)
    );
    assert_eq!(
        classify("/dav/principals/acme/anna/".to_owned()).await,
        internal(&anna, PrincipalKind::User)
    );
    assert_eq!(
        classify("/dav/calendars/acme/anna/".to_owned()).await,
        internal(&anna, PrincipalKind::User)
    );
    assert_eq!(
        classify(format!("urn:uuid:{}", team.id)).await,
        internal(&team, PrincipalKind::Group),
        "groups are classified as such; they are not expanded"
    );
    assert_eq!(
        classify("mailto:olga@other.example".to_owned()).await,
        AddressClass::External,
        "another tenant's principals are external"
    );
    assert_eq!(
        classify("mailto:guest@example.org".to_owned()).await,
        AddressClass::External
    );
    assert_eq!(
        classify("urn:uuid:00000000-0000-0000-0000-00000000ffff".to_owned()).await,
        AddressClass::Unresolvable
    );
    assert_eq!(
        classify("/dav/principals/other/olga/".to_owned()).await,
        AddressClass::Unresolvable
    );
}

#[tokio::test]
async fn principal_administration_needs_its_scopes_and_lists_in_pages() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    for index in 0..4 {
        world.user(&acme, &format!("user-{index}")).await;
    }
    let team = world.group(&acme, "team", &[&anna]).await;
    let reader = world.tenant_token(&acme, ScopeSet::of(&[Scope::PrincipalsRead]));
    let writer = world.tenant_token(&acme, ScopeSet::of(&[Scope::PrincipalsWrite]));

    // Reading needs principals:read, writing principals:write; DAV sessions administer nothing.
    assert!(world.services.principals.get(&reader, &anna.name).await.is_ok());
    assert_eq!(
        world
            .services
            .principals
            .get(&writer, &anna.name)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );
    let spec = PrincipalSpec {
        name: name("new"),
        body: principal_body(&acme, "new", PrincipalKind::User),
    };
    assert_eq!(
        world
            .services
            .principals
            .upsert(&reader, spec.clone(), Conditions::none())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );
    assert!(
        world
            .services
            .principals
            .upsert(&writer, spec, Conditions::none())
            .await
            .unwrap()
            .created
    );
    assert_eq!(
        world
            .services
            .principals
            .list(
                &world.dav(&acme, &anna),
                PrincipalFilter::default(),
                PageRequest::first()
            )
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );

    // Filters, order and pages.
    let groups = world
        .services
        .principals
        .list(
            &reader,
            PrincipalFilter {
                kind: Some(PrincipalKind::Group),
                external_ref: None,
            },
            PageRequest::first(),
        )
        .await
        .unwrap();
    assert_eq!(
        groups.items.iter().map(|view| view.id).collect::<Vec<_>>(),
        vec![team.id]
    );
    let mut seen = Vec::new();
    let mut page = PageRequest::with_limit(2);
    loop {
        let batch = world
            .services
            .principals
            .list(&reader, PrincipalFilter::default(), page.clone())
            .await
            .unwrap();
        assert!(batch.items.len() <= 2);
        seen.extend(batch.items.iter().map(|view| view.id));
        match batch.next_cursor {
            Some(cursor) => page = PageRequest::with_limit(2).after(cursor),
            None => break,
        }
    }
    assert_eq!(seen.len(), 7, "anna, four users, the group and the new user");
    let mut sorted = seen.clone();
    sorted.sort();
    assert_eq!(seen, sorted, "ordered by id");
}

#[tokio::test]
async fn deleting_a_group_ends_the_access_of_its_members_at_once_and_tells_the_world() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let carl = world.user(&acme, "carl").await;
    let team = world.group(&acme, "team", &[&anna, &ben]).await;
    world.calendar(&acme, &team, "shared", CalendarKind::Group).await;
    let admin = world.admin(&acme);
    // An API grant to a third person, with the invitation of another one that is still waiting.
    world
        .services
        .sharing
        .put_grant(
            &admin,
            davhaven_testkit::davhaven_app::services::GrantSpec {
                calendar: world.key(&team, "shared"),
                grantee: carl.name.clone(),
                body: davhaven_testkit::davhaven_wire::GrantWrite {
                    access: davhaven_testkit::davhaven_domain::GrantAccess::Read,
                    required: false,
                },
            },
            Conditions::none(),
        )
        .await
        .unwrap();
    // Both members use the calendar: it is in their homes.
    for who in [&anna, &ben] {
        let home = world
            .services
            .calendars
            .list_home(&world.dav(&acme, who), &who.name)
            .await
            .unwrap();
        assert!(home.iter().any(|view| view.kind == CalendarKind::Group), "{}", who.name);
    }
    let shared_path = world.collection(&acme, &anna, "shared");
    assert!(
        world
            .services
            .calendars
            .get_collection(&world.dav(&acme, &anna), &shared_path)
            .await
            .is_ok()
    );
    let grants = world.events_of(&acme, EventType::GrantDeleted).await.len();
    let memberships = world.events_of(&acme, EventType::MembershipChanged).await.len();
    let version = world.services.principals.get(&admin, &team.name).await.unwrap().version;

    world
        .services
        .principals
        .delete(
            &admin,
            &team.name,
            DeleteOptions {
                conditions: Conditions::if_match(version),
                ..DeleteOptions::default()
            },
        )
        .await
        .unwrap();

    // The members keep nothing the group gave them: the calendar answers 404 and is not in their homes any more.
    for who in [&anna, &ben] {
        let dav = world.dav(&acme, who);
        let home = world.services.calendars.list_home(&dav, &who.name).await.unwrap();
        assert!(
            home.iter().all(|view| view.kind != CalendarKind::Group),
            "{} still lists the group calendar",
            who.name
        );
    }
    assert_eq!(
        world
            .services
            .calendars
            .get_collection(&world.dav(&acme, &anna), &shared_path)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    // The shares of the group's calendars end with it, and everything is announced like the API's own removals.
    assert_eq!(
        world.events_of(&acme, EventType::GrantDeleted).await.len(),
        grants + 1,
        "the API grant of the calendar"
    );
    assert_eq!(
        world.events_of(&acme, EventType::MembershipChanged).await.len(),
        memberships + 1,
        "the members left the group"
    );
    let actions = world.audit_actions(&acme).await;
    assert!(actions.contains(&"grant.deleted".to_owned()), "{actions:?}");
    assert_eq!(
        world.services.principals.members(&admin, &team.name).await.unwrap_err().kind(),
        ErrorKind::NotFound,
        "the deleted group is gone"
    );
}

#[tokio::test]
async fn deleting_a_user_announces_the_grants_and_memberships_it_removes() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let team = world.group(&acme, "team", &[&anna]).await;
    let admin = world.admin(&acme);
    // Ben has a calendar that Anna can read, and Anna one that Ben can read.
    world.calendar(&acme, &ben, "plans", CalendarKind::User).await;
    world.calendar(&acme, &anna, "notes", CalendarKind::User).await;
    for (owner, slug, grantee) in [(&ben, "plans", &anna), (&anna, "notes", &ben)] {
        world
            .services
            .sharing
            .put_grant(
                &admin,
                davhaven_testkit::davhaven_app::services::GrantSpec {
                    calendar: world.key(owner, slug),
                    grantee: grantee.name.clone(),
                    body: davhaven_testkit::davhaven_wire::GrantWrite {
                        access: davhaven_testkit::davhaven_domain::GrantAccess::Read,
                        required: false,
                    },
                },
                Conditions::none(),
            )
            .await
            .unwrap();
    }
    let notes_before = world
        .services
        .calendars
        .get(&admin, &world.key(&ben, "plans"))
        .await
        .unwrap()
        .sync_token
        .seq;
    let version = world.services.principals.get(&admin, &anna.name).await.unwrap().version;
    world
        .services
        .principals
        .delete(
            &admin,
            &anna.name,
            DeleteOptions {
                conditions: Conditions::if_match(version),
                ..DeleteOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        world.events_of(&acme, EventType::GrantDeleted).await.len(),
        2,
        "the grant to Anna and the grant of Anna's calendar"
    );
    assert_eq!(
        world.events_of(&acme, EventType::MembershipChanged).await.len(),
        2,
        "the creation of the group's membership and Anna leaving it"
    );
    let actions = world.audit_actions(&acme).await;
    assert_eq!(actions.iter().filter(|action| *action == "grant.deleted").count(), 2);
    let notes_after = world
        .services
        .calendars
        .get(&admin, &world.key(&ben, "plans"))
        .await
        .unwrap()
        .sync_token
        .seq;
    assert!(
        notes_after > notes_before,
        "the CTag of a calendar whose sharing ended moves"
    );
    let _ = team;
}

#[tokio::test]
async fn a_put_without_a_status_keeps_the_stored_one_and_a_principal_url_of_another_deployment_is_no_address_here() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let dav = world.dav(&acme, &anna);

    // Suspended explicitly; a reconciler that does not mention the status leaves it so.
    let mut suspended = principal_body(&acme, "ben", PrincipalKind::User);
    suspended.status = Some(PrincipalStatus::Suspended);
    world.principal_write(&acme, "ben", suspended).await.unwrap();
    let omitted = principal_body(&acme, "ben", PrincipalKind::User);
    assert_eq!(omitted.status, None);
    let view = world.principal_write(&acme, "ben", omitted).await.unwrap();
    assert_eq!(
        view.status,
        PrincipalStatus::Suspended,
        "an absent status is not `active`"
    );
    let mut active = principal_body(&acme, "ben", PrincipalKind::User);
    active.status = Some(PrincipalStatus::Active);
    assert_eq!(
        world.principal_write(&acme, "ben", active).await.unwrap().status,
        PrincipalStatus::Active
    );

    // Only a path or an address on the DAV origin of this deployment names a principal here.
    let classify = |text: &str| {
        let world = &world;
        let dav = &dav;
        let text = text.to_owned();
        async move {
            world
                .services
                .principals
                .resolve_address(dav, &address(&text))
                .await
                .unwrap()
        }
    };
    let internal = |kind| AddressClass::Internal {
        principal: anna.id,
        name: anna.name.clone(),
        kind,
    };
    assert_eq!(
        classify("https://cal.example.org/dav/principals/acme/anna/").await,
        internal(PrincipalKind::User)
    );
    assert_eq!(
        classify("https://other-davhaven.example/dav/principals/acme/anna/").await,
        AddressClass::Unresolvable,
        "the same path on another host is another server's principal"
    );
    assert_eq!(
        classify("/dav/principals/acme/anna/").await,
        internal(PrincipalKind::User)
    );
}

#[tokio::test]
async fn the_mail_address_of_a_deleted_principal_stays_reserved_and_is_not_external() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let admin = world.admin(&acme);
    let version = world.services.principals.get(&admin, &ben.name).await.unwrap().version;
    world
        .services
        .principals
        .delete(
            &admin,
            &ben.name,
            DeleteOptions {
                conditions: Conditions::if_match(version),
                ..DeleteOptions::default()
            },
        )
        .await
        .unwrap();
    let class = world
        .services
        .principals
        .resolve_address(&world.dav(&acme, &anna), &address("mailto:ben@acme.example"))
        .await
        .unwrap();
    assert_eq!(
        class,
        AddressClass::Unresolvable,
        "mail to a reserved address must not leave the server as if nobody owned it"
    );
    let stranger = world
        .services
        .principals
        .resolve_address(&world.dav(&acme, &anna), &address("mailto:nobody@example.org"))
        .await
        .unwrap();
    assert_eq!(stranger, AddressClass::External);
}

/// The problem code a client of the management API receives for `error`.
fn problem_code(error: &davhaven_testkit::davhaven_app::AppError) -> &'static str {
    davhaven_testkit::davhaven_wire::ProblemCode::from_error(error.kind(), error.precondition()).code()
}

#[tokio::test]
async fn a_deleted_principal_keeps_its_name_external_reference_and_addresses_reserved_until_the_purge() {
    let world = World::new();
    let acme = world.org("acme").await;
    let admin = world.admin(&acme);
    let upsert = |who: &str, body: PrincipalWrite, conditions: Conditions| {
        let world = &world;
        let admin = admin.clone();
        let spec = PrincipalSpec { name: name(who), body };
        async move { world.services.principals.upsert(&admin, spec, conditions).await }
    };

    // Anna has an external reference and a further address; she is deleted without a purge.
    let mut body = principal_body(&acme, "anna", PrincipalKind::User);
    body.external_ref = Some("hr-1".to_owned());
    body.addresses = vec![address("mailto:anna.sales@acme.example")];
    let anna = world.principal_write(&acme, "anna", body.clone()).await.unwrap();
    world
        .services
        .principals
        .delete(
            &admin,
            &anna.name,
            DeleteOptions {
                conditions: Conditions::if_match(anna.version),
                ..DeleteOptions::default()
            },
        )
        .await
        .unwrap();
    let listed = world
        .services
        .principals
        .list(
            &admin,
            PrincipalFilter {
                external_ref: Some("hr-1".to_owned()),
                ..PrincipalFilter::default()
            },
            PageRequest::first(),
        )
        .await
        .unwrap();
    assert!(
        listed.items.is_empty(),
        "the deleted principal is hidden from the listing"
    );

    // The name: `If-None-Match: *` answers 412 like for every name that exists, and tells nothing about the hidden
    // principal (the generic problem of its status, no detail, no field).
    let taken = upsert("anna", body.clone(), Conditions::create_only())
        .await
        .unwrap_err();
    assert_eq!(taken.kind(), ErrorKind::PreconditionFailed);
    assert_eq!(problem_code(&taken), "precondition-failed");
    assert_eq!(
        taken.public_message().as_str(),
        "The resource has changed; reload it and try again.",
        "the generic text of the status: nothing about the hidden principal's data"
    );
    assert!(taken.field_errors().is_empty());
    // Without a condition the name is a conflict with the state of the resource, not a way to take it over; it has a
    // code of its own, so that a declarative client can tell it from a collision with a live principal.
    let overwritten = upsert("anna", body, Conditions::none()).await.unwrap_err();
    assert_eq!(overwritten.kind(), ErrorKind::Conflict);
    assert_eq!(problem_code(&overwritten), "name-reserved");
    assert_eq!(
        overwritten.precondition(),
        Some(&davhaven_testkit::davhaven_domain::Precondition::NameReserved)
    );
    assert!(overwritten.field_errors().is_empty());

    // The external reference of a new principal: 409 `external-ref-reserved`, so that the client can purge or wait.
    let mut ben = principal_body(&acme, "ben", PrincipalKind::User);
    ben.external_ref = Some("hr-1".to_owned());
    let reserved = upsert("ben", ben, Conditions::create_only()).await.unwrap_err();
    assert_eq!(reserved.kind(), ErrorKind::Conflict);
    assert_eq!(problem_code(&reserved), "external-ref-reserved");
    assert_eq!(
        reserved.precondition(),
        Some(&davhaven_testkit::davhaven_domain::Precondition::ExternalRefReserved)
    );
    assert!(reserved.field_errors().is_empty());
    assert!(
        world.services.principals.get(&admin, &name("ben")).await.is_err(),
        "nothing was created"
    );

    // The same for an address, whether it is the primary one or a further one.
    let mut cara = principal_body(&acme, "cara", PrincipalKind::User);
    cara.email = Some(Email::parse("anna@acme.example").unwrap());
    let reserved = upsert("cara", cara, Conditions::none()).await.unwrap_err();
    assert_eq!(reserved.kind(), ErrorKind::Conflict);
    assert_eq!(problem_code(&reserved), "address-reserved");
    let mut dora = principal_body(&acme, "dora", PrincipalKind::User);
    dora.addresses = vec![address("mailto:anna.sales@acme.example")];
    let reserved = upsert("dora", dora, Conditions::none()).await.unwrap_err();
    assert_eq!(problem_code(&reserved), "address-reserved");

    // A principal that exists and replaces its values with reserved ones gets the same answers, and keeps its own.
    let erin = world.user(&acme, "erin").await;
    let mut takes_ref = principal_body(&acme, "erin", PrincipalKind::User);
    takes_ref.external_ref = Some("hr-1".to_owned());
    assert_eq!(
        problem_code(&upsert("erin", takes_ref, Conditions::none()).await.unwrap_err()),
        "external-ref-reserved"
    );
    let mut takes_address = principal_body(&acme, "erin", PrincipalKind::User);
    takes_address.addresses = vec![address("mailto:anna@acme.example")];
    assert_eq!(
        problem_code(&upsert("erin", takes_address, Conditions::none()).await.unwrap_err()),
        "address-reserved"
    );
    let unchanged = world.services.principals.get(&admin, &erin.name).await.unwrap();
    assert_eq!((unchanged.external_ref, unchanged.version), (None, 1));

    // A live principal that holds a value is the plain conflict: only deleted principals have the dedicated rows.
    let mut frank = principal_body(&acme, "frank", PrincipalKind::User);
    frank.external_ref = Some("hr-2".to_owned());
    world.principal_write(&acme, "frank", frank).await.unwrap();
    let mut grace = principal_body(&acme, "grace", PrincipalKind::User);
    grace.external_ref = Some("hr-2".to_owned());
    let conflict = upsert("grace", grace, Conditions::none()).await.unwrap_err();
    assert_eq!(conflict.kind(), ErrorKind::Conflict);
    assert_eq!(problem_code(&conflict), "conflict");
    let mut heidi = principal_body(&acme, "heidi", PrincipalKind::User);
    heidi.email = Some(Email::parse("frank@acme.example").unwrap());
    let conflict = upsert("heidi", heidi, Conditions::none()).await.unwrap_err();
    assert_eq!(problem_code(&conflict), "conflict");

    // The purge frees the name, the external reference and the addresses at once.
    let mut zed = principal_body(&acme, "zed", PrincipalKind::User);
    zed.external_ref = Some("hr-9".to_owned());
    zed.addresses = vec![address("mailto:zed.sales@acme.example")];
    let zed_view = world.principal_write(&acme, "zed", zed.clone()).await.unwrap();
    world
        .services
        .principals
        .delete(
            &admin,
            &zed_view.name,
            DeleteOptions {
                purge: true,
                conditions: Conditions::if_match(zed_view.version),
                ..DeleteOptions::default()
            },
        )
        .await
        .unwrap();
    let mut successor = principal_body(&acme, "zed-2", PrincipalKind::User);
    successor.external_ref = Some("hr-9".to_owned());
    successor.addresses = zed.addresses;
    upsert("zed-2", successor, Conditions::create_only()).await.unwrap();
    let mut again = principal_body(&acme, "zed", PrincipalKind::User);
    again.email = Some(Email::parse("zed.again@acme.example").unwrap());
    upsert("zed", again, Conditions::create_only()).await.unwrap();
}
