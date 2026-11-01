//! Required calendars and the bindings of a home (backlog 55): a grant marked `required` keeps a calendar in the home of the
//! people it reaches, an optional one lets them hide it, and the management API lists the bindings of a principal and shows a
//! hidden one again.

use davhaven_testkit::davhaven_app::error::AppError;
use davhaven_testkit::davhaven_app::services::{
    BindingFilter, Conditions, GrantSpec, PageRequest, ShareRequest, ShareeSet, Upserted,
};
use davhaven_testkit::davhaven_domain::{
    CalendarKind, CalendarUserAddress, ErrorKind, GrantAccess, Precondition, PrincipalKind, Privilege, RequestContext,
    Scope, ScopeSet,
};
use davhaven_testkit::davhaven_wire::{GrantView, GrantWrite, HomeBindingView};

use super::support::{Fixture, Org, Person, World, fixture};

/// The world of these tests: two colleagues and a group of both (`staff`), and the owner `anna` of the fixture.
struct Setting {
    world: World,
    acme: Org,
    anna: Person,
    ben: Person,
    carla: Person,
    staff: Person,
}

async fn setting() -> Setting {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let carla = world.user(&acme, "carla").await;
    let staff = world.group(&acme, "staff", &[&ben, &carla]).await;
    Setting {
        world,
        acme,
        anna,
        ben,
        carla,
        staff,
    }
}

/// Grants `grantee` the calendar `calendar` of `owner` through the management API.
async fn grant(
    world: &World,
    org: &Org,
    owner: &Person,
    calendar: &str,
    grantee: &Person,
    required: bool,
) -> GrantView {
    world
        .services
        .sharing
        .put_grant(
            &world.admin(org),
            GrantSpec {
                calendar: world.key(owner, calendar),
                grantee: grantee.name.clone(),
                body: GrantWrite {
                    access: GrantAccess::Read,
                    required,
                },
            },
            Conditions::none(),
        )
        .await
        .unwrap()
        .value
}

/// The calendars of the home as the person's calendar app lists them: the slugs of the collections.
async fn home_of(world: &World, org: &Org, person: &Person) -> Vec<String> {
    world
        .services
        .calendars
        .list_home(&world.dav(org, person), &person.name)
        .await
        .unwrap()
        .iter()
        .map(|view| view.path.format())
        .collect()
}

/// The bindings of the home of `person` as the management API lists them.
async fn bindings(world: &World, org: &Org, person: &Person, hidden: Option<bool>) -> Vec<HomeBindingView> {
    world
        .services
        .calendars
        .list_bindings(
            &world.admin(org),
            &person.name,
            BindingFilter { hidden },
            PageRequest::first(),
        )
        .await
        .unwrap()
        .items
}

/// What a calendar app does when the user removes a calendar from the sidebar: `DELETE` of the collection.
async fn delete(
    world: &World,
    org: &Org,
    person: &Person,
    slug: &str,
) -> Result<(), davhaven_testkit::davhaven_app::error::AppError> {
    world
        .services
        .calendars
        .delete_collection(
            &world.dav(org, person),
            &world.collection(org, person, slug),
            Conditions::none(),
        )
        .await
}

fn is_unbind_refusal(error: &davhaven_testkit::davhaven_app::error::AppError) -> bool {
    error.kind() == ErrorKind::Forbidden
        && matches!(
            error.precondition(),
            Some(Precondition::NeedPrivileges(needed))
                if needed.iter().any(|(_, privilege)| *privilege == Privilege::Unbind)
        )
}

#[tokio::test]
async fn a_required_grant_keeps_the_calendar_in_the_home_and_an_optional_one_lets_it_be_hidden() {
    let Setting {
        world,
        acme,
        anna,
        ben,
        carla,
        staff,
    } = setting().await;
    let robot = world.principal(&acme, "robot", PrincipalKind::Service).await;
    world.calendar(&acme, &robot, "courses", CalendarKind::Managed).await;
    world.calendar(&acme, &anna, "projects", CalendarKind::User).await;
    let required = grant(&world, &acme, &robot, "courses", &staff, true).await;
    assert!(required.required, "the grant says so");
    let optional = grant(&world, &acme, &anna, "projects", &staff, false).await;
    assert!(!optional.required);
    let before = home_of(&world, &acme, &ben).await;
    assert_eq!(
        before.len(),
        3,
        "the personal calendar and the two of the group: {before:?}"
    );

    // The calendar that is required stays, however often the calendar app tries.
    for _ in 0..2 {
        let error = delete(&world, &acme, &ben, "courses").await.unwrap_err();
        assert!(is_unbind_refusal(&error), "{error:?}");
    }
    assert_eq!(
        home_of(&world, &acme, &ben).await,
        before,
        "nothing changed in the home"
    );
    let calendar = world
        .services
        .calendars
        .get_collection(&world.dav(&acme, &ben), &world.collection(&acme, &ben, "courses"))
        .await
        .unwrap();
    assert!(calendar.calendar.is_some(), "the collection still resolves");

    // The optional one is hidden for the person who deleted it, and only for them.
    delete(&world, &acme, &ben, "projects").await.unwrap();
    assert_eq!(home_of(&world, &acme, &ben).await.len(), 2);
    assert_eq!(home_of(&world, &acme, &carla).await.len(), 3, "carla still has it");

    // The management API shows what was hidden, and what cannot be.
    let hidden = bindings(&world, &acme, &ben, Some(true)).await;
    assert_eq!(hidden.len(), 1, "{hidden:?}");
    let binding = &hidden[0];
    assert_eq!(
        (binding.calendar.as_str(), binding.owner.as_str()),
        ("projects", "anna")
    );
    assert!(binding.hidden && !binding.required);
    assert_eq!(binding.kind, CalendarKind::User);
    assert_eq!(binding.principal, ben.name);
    assert!(
        binding.dav_url.as_str().ends_with("/dav/calendars/acme/ben/projects/"),
        "{}",
        binding.dav_url
    );
    let all = bindings(&world, &acme, &ben, None).await;
    assert_eq!(all.len(), 3, "hidden ones are listed with the others");
    let visible = bindings(&world, &acme, &ben, Some(false)).await;
    assert_eq!(visible.len(), 2);
    let courses = visible.iter().find(|view| view.calendar.as_str() == "courses").unwrap();
    assert!(
        courses.required && !courses.hidden,
        "the managed calendar is required for ben"
    );
    assert!(
        visible
            .iter()
            .filter(|view| view.calendar.as_str() != "courses")
            .all(|view| !view.required),
        "nothing else is"
    );

    // Restoring shows it again, once; restoring a visible binding changes nothing.
    let admin = world.admin(&acme);
    let restored = world
        .services
        .calendars
        .restore_binding(&admin, &ben.name, &binding.slug)
        .await
        .unwrap();
    assert!(!restored.hidden);
    assert!(restored.version > binding.version);
    assert_eq!(home_of(&world, &acme, &ben).await.len(), 3);
    assert!(
        world
            .services
            .calendars
            .get_collection(&world.dav(&acme, &ben), &world.collection(&acme, &ben, "projects"))
            .await
            .is_ok(),
        "the collection resolves again"
    );
    let again = world
        .services
        .calendars
        .restore_binding(&admin, &ben.name, &binding.slug)
        .await
        .unwrap();
    assert_eq!(again, restored, "a binding that is visible is returned as it is");
    assert!(bindings(&world, &acme, &ben, Some(true)).await.is_empty());
}

#[tokio::test]
async fn marking_a_grant_required_shows_again_what_the_people_it_reaches_had_hidden() {
    let Setting {
        world,
        acme,
        anna,
        ben,
        carla,
        staff,
    } = setting().await;
    let dora = world.user(&acme, "dora").await;
    world.calendar(&acme, &anna, "projects", CalendarKind::User).await;
    grant(&world, &acme, &anna, "projects", &staff, false).await;
    // `dora` has the calendar through a grant of her own, which stays optional.
    grant(&world, &acme, &anna, "projects", &dora, false).await;
    for person in [&ben, &carla, &dora] {
        home_of(&world, &acme, person).await;
        delete(&world, &acme, person, "projects").await.unwrap();
        assert_eq!(bindings(&world, &acme, person, Some(true)).await.len(), 1);
    }

    let marked = grant(&world, &acme, &anna, "projects", &staff, true).await;
    assert!(marked.required);
    for person in [&ben, &carla] {
        assert!(
            bindings(&world, &acme, person, Some(true)).await.is_empty(),
            "{} has nothing hidden any more",
            person.name
        );
        assert!(
            home_of(&world, &acme, person)
                .await
                .iter()
                .any(|path| path.ends_with("/projects/")),
            "{} lists it again",
            person.name
        );
        let error = delete(&world, &acme, person, "projects").await.unwrap_err();
        assert!(is_unbind_refusal(&error), "{error:?}");
    }
    assert_eq!(
        bindings(&world, &acme, &dora, Some(true)).await.len(),
        1,
        "the grant of somebody else's group does not reach dora"
    );

    // Taking the flag back makes the calendar optional again.
    let optional = grant(&world, &acme, &anna, "projects", &staff, false).await;
    assert!(!optional.required);
    delete(&world, &acme, &ben, "projects").await.unwrap();
}

#[tokio::test]
async fn a_group_can_be_granted_its_own_calendar_to_make_it_required_for_its_members() {
    let Setting {
        world,
        acme,
        anna,
        ben,
        staff,
        ..
    } = setting().await;
    world.calendar(&acme, &staff, "board", CalendarKind::Group).await;
    home_of(&world, &acme, &ben).await;

    // The members have the calendar through the group, and may hide it, until the group's own grant says otherwise.
    let marked = grant(&world, &acme, &staff, "board", &staff, true).await;
    assert!(marked.required);
    assert_eq!(marked.grantee, staff.name);
    let error = delete(&world, &acme, &ben, "board").await.unwrap_err();
    assert!(is_unbind_refusal(&error), "{error:?}");
    let listed = bindings(&world, &acme, &ben, None).await;
    assert!(
        listed
            .iter()
            .any(|view| view.calendar.as_str() == "board" && view.required),
        "{listed:?}"
    );

    // Only a group may be granted the calendar it owns: the owner of any other calendar has access already.
    let error = world
        .services
        .sharing
        .put_grant(
            &world.admin(&acme),
            GrantSpec {
                calendar: world.key(&anna, "personal"),
                grantee: anna.name.clone(),
                body: GrantWrite {
                    access: GrantAccess::Read,
                    required: true,
                },
            },
            Conditions::none(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Invalid);
}

#[tokio::test]
async fn a_client_cannot_change_or_remove_a_required_grant() {
    let Setting {
        world,
        acme,
        anna,
        carla,
        ..
    } = setting().await;
    world.calendar(&acme, &anna, "projects", CalendarKind::User).await;
    grant(&world, &acme, &anna, "projects", &carla, true).await;
    let owners = world.dav(&acme, &anna);
    let collection = world.collection(&acme, &anna, "projects");
    let carla_address = CalendarUserAddress::parse("mailto:carla@acme.example").unwrap();

    let removed = world
        .services
        .sharing
        .share(
            &owners,
            &collection,
            ShareRequest {
                set: Vec::new(),
                remove: vec![carla_address.clone()],
            },
        )
        .await
        .unwrap();
    let error = removed[0]
        .error
        .as_ref()
        .expect("the operator's grant is not the client's");
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    let changed = world
        .services
        .sharing
        .share(
            &owners,
            &collection,
            ShareRequest {
                set: vec![ShareeSet {
                    address: carla_address,
                    common_name: None,
                    summary: None,
                    access: GrantAccess::ReadWrite,
                }],
                remove: Vec::new(),
            },
        )
        .await
        .unwrap();
    let error = changed[0].error.as_ref().expect("nor is its access");
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    let grants = world
        .services
        .sharing
        .list_grants(&world.admin(&acme), &world.key(&anna, "projects"), PageRequest::first())
        .await
        .unwrap()
        .items;
    assert_eq!(grants.len(), 1);
    assert!(
        grants[0].required && grants[0].access == GrantAccess::Read,
        "{grants:?}"
    );
}

#[tokio::test]
async fn only_tenant_administrators_with_the_scopes_list_and_restore_bindings() {
    let Setting {
        world,
        acme,
        anna,
        ben,
        staff,
        ..
    } = setting().await;
    world.calendar(&acme, &anna, "projects", CalendarKind::User).await;
    grant(&world, &acme, &anna, "projects", &staff, false).await;
    home_of(&world, &acme, &ben).await;
    delete(&world, &acme, &ben, "projects").await.unwrap();
    let hidden = bindings(&world, &acme, &ben, Some(true)).await;
    let slug = hidden[0].slug.clone();
    let calendars = &world.services.calendars;

    let reader = world.tenant_token(&acme, ScopeSet::of(&[Scope::CalendarsRead]));
    let writer = world.tenant_token(&acme, ScopeSet::of(&[Scope::CalendarsWrite]));
    let name = &ben.name;
    let list = |ctx| async move {
        calendars
            .list_bindings(&ctx, name, BindingFilter::default(), PageRequest::first())
            .await
    };
    assert!(list(reader.clone()).await.is_ok(), "calendars:read lists");
    assert_eq!(list(writer.clone()).await.unwrap_err().kind(), ErrorKind::Forbidden);
    assert_eq!(
        calendars
            .restore_binding(&reader, &ben.name, &slug)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden,
        "listing is not restoring"
    );
    assert!(
        bindings(&world, &acme, &ben, Some(true)).await.len() == 1,
        "a refusal restores nothing"
    );
    // A person acts as themselves: neither their calendar app nor their own token administers a home, not even their own.
    for ctx in [
        world.dav(&acme, &ben),
        world.api(&acme, &ben, &[Scope::CalendarsRead, Scope::CalendarsWrite]),
    ] {
        assert_eq!(list(ctx.clone()).await.unwrap_err().kind(), ErrorKind::Forbidden);
        assert_eq!(
            calendars
                .restore_binding(&ctx, &ben.name, &slug)
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::Forbidden
        );
        assert_eq!(
            bindings(&world, &acme, &ben, Some(true)).await.len(),
            1,
            "a refused restore shows nothing again"
        );
    }
    assert!(calendars.restore_binding(&writer, &ben.name, &slug).await.is_ok());

    // What does not exist, and what belongs to another tenant, is not there.
    let nobody = world.user(&acme, "nobody").await;
    assert!(
        bindings(&world, &acme, &nobody, None).await.len() == 1,
        "the personal calendar only"
    );
    let admin = world.admin(&acme);
    let unknown = davhaven_testkit::davhaven_domain::PrincipalName::parse("nonexistent").unwrap();
    assert_eq!(
        calendars
            .list_bindings(&admin, &unknown, BindingFilter::default(), PageRequest::first())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    let no_such = davhaven_testkit::davhaven_domain::CalendarSlug::parse("no-such-calendar").unwrap();
    assert_eq!(
        calendars
            .restore_binding(&admin, &ben.name, &no_such)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    let globex = world.org("globex").await;
    assert_eq!(
        calendars
            .list_bindings(
                &world.admin(&globex),
                &ben.name,
                BindingFilter::default(),
                PageRequest::first()
            )
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound,
        "the principals of another tenant are not visible"
    );
    assert_eq!(
        calendars
            .restore_binding(&world.admin(&globex), &ben.name, &slug)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
}

#[tokio::test]
async fn the_bindings_of_a_home_are_listed_in_pages() {
    let Setting {
        world,
        acme,
        anna,
        ben,
        staff,
        ..
    } = setting().await;
    for slug in ["alpha", "beta"] {
        world.calendar(&acme, &anna, slug, CalendarKind::User).await;
        grant(&world, &acme, &anna, slug, &staff, false).await;
    }
    home_of(&world, &acme, &ben).await;
    let admin = world.admin(&acme);
    let first = world
        .services
        .calendars
        .list_bindings(&admin, &ben.name, BindingFilter::default(), PageRequest::with_limit(2))
        .await
        .unwrap();
    assert_eq!(first.items.len(), 2);
    let cursor = first.next_cursor.clone().expect("there is a third binding");
    let second = world
        .services
        .calendars
        .list_bindings(
            &admin,
            &ben.name,
            BindingFilter::default(),
            PageRequest::with_limit(2).after(cursor.clone()),
        )
        .await
        .unwrap();
    assert_eq!(second.items.len(), 1);
    assert!(second.next_cursor.is_none());
    let mut seen: Vec<_> = first.items.iter().chain(&second.items).map(|view| view.id).collect();
    seen.dedup();
    assert_eq!(seen.len(), 3, "every binding once");
    // A cursor belongs to its listing: another filter refuses it.
    let error = world
        .services
        .calendars
        .list_bindings(
            &admin,
            &ben.name,
            BindingFilter { hidden: Some(true) },
            PageRequest::with_limit(2).after(cursor),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Invalid);
}

#[tokio::test]
async fn somebody_who_hid_a_calendar_and_then_joins_the_group_it_is_required_for_finds_it_again() {
    let Setting { world, acme, anna, .. } = setting().await;
    let dora = world.user(&acme, "dora").await;
    let erin = world.user(&acme, "erin").await;
    let crew = world.group(&acme, "crew", &[]).await;
    world.calendar(&acme, &anna, "projects", CalendarKind::User).await;
    // Both have the calendar through a grant of their own, which is optional, and hide it.
    for person in [&dora, &erin] {
        grant(&world, &acme, &anna, "projects", person, false).await;
        home_of(&world, &acme, person).await;
        delete(&world, &acme, person, "projects").await.unwrap();
    }
    // The calendar is required for the group `crew`, which has no members yet: nothing reaches them.
    grant(&world, &acme, &anna, "projects", &crew, true).await;
    for person in [&dora, &erin] {
        assert_eq!(bindings(&world, &acme, person, Some(true)).await.len(), 1);
    }

    // Joining the group brings the calendar back: it is required for them from then on.
    let admin = world.admin(&acme);
    world
        .services
        .principals
        .add_member(&admin, &crew.name, &dora.name)
        .await
        .unwrap();
    assert!(bindings(&world, &acme, &dora, Some(true)).await.is_empty());
    let listed = bindings(&world, &acme, &dora, None).await;
    assert!(
        listed
            .iter()
            .any(|view| view.calendar.as_str() == "projects" && view.required && !view.hidden),
        "{listed:?}"
    );
    assert!(
        home_of(&world, &acme, &dora)
            .await
            .iter()
            .any(|path| path.ends_with("/projects/"))
    );
    let error = delete(&world, &acme, &dora, "projects").await.unwrap_err();
    assert!(is_unbind_refusal(&error), "{error:?}");

    // So does a membership that is replaced as a whole.
    world
        .services
        .principals
        .set_members(&admin, &crew.name, vec![dora.name.clone(), erin.name.clone()])
        .await
        .unwrap();
    assert!(bindings(&world, &acme, &erin, Some(true)).await.is_empty());
    assert!(
        home_of(&world, &acme, &erin)
            .await
            .iter()
            .any(|path| path.ends_with("/projects/"))
    );
    let restored = world
        .audit_actions(&acme)
        .await
        .iter()
        .filter(|action| action.as_str() == "binding.restored")
        .count();
    assert_eq!(restored, 2, "each binding that came back is in the audit log");
}

#[tokio::test]
async fn a_binding_of_a_calendar_out_of_reach_is_neither_listed_nor_restored() {
    let Setting {
        world,
        acme,
        anna,
        ben,
        carla,
        staff,
    } = setting().await;
    world.calendar(&acme, &anna, "projects", CalendarKind::User).await;
    grant(&world, &acme, &anna, "projects", &staff, false).await;
    for person in [&ben, &carla] {
        home_of(&world, &acme, person).await;
    }
    delete(&world, &acme, &ben, "projects").await.unwrap();
    let slug = bindings(&world, &acme, &ben, Some(true)).await[0].slug.clone();
    let admin = world.admin(&acme);

    // `ben` leaves the group and the grant of the group goes: the bindings stay in the store, the homes do not list them.
    world
        .services
        .principals
        .remove_member(&admin, &staff.name, &ben.name)
        .await
        .unwrap();
    world
        .services
        .sharing
        .delete_grant(&admin, &world.key(&anna, "projects"), &staff.name, Conditions::none())
        .await
        .unwrap();
    for person in [&ben, &carla] {
        assert!(
            bindings(&world, &acme, person, None)
                .await
                .iter()
                .all(|view| view.calendar.as_str() != "projects"),
            "{} no longer has the calendar",
            person.name
        );
        assert!(
            home_of(&world, &acme, person)
                .await
                .iter()
                .all(|path| !path.ends_with("/projects/"))
        );
    }
    assert!(bindings(&world, &acme, &ben, Some(true)).await.is_empty());
    let calendars = &world.services.calendars;
    for person in [&ben, &carla] {
        let error = calendars
            .restore_binding(&admin, &person.name, &slug)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound, "{}", person.name);
    }
}

/// `put_grant` as `ctx` for the calendar `target` (the owner and the slug).
async fn put_as(
    world: &World,
    ctx: &RequestContext,
    target: (&Person, &str),
    grantee: &Person,
    access: GrantAccess,
    required: bool,
) -> Result<Upserted<GrantView>, AppError> {
    world
        .services
        .sharing
        .put_grant(
            ctx,
            GrantSpec {
                calendar: world.key(target.0, target.1),
                grantee: grantee.name.clone(),
                body: GrantWrite { access, required },
            },
            Conditions::none(),
        )
        .await
}

#[tokio::test]
async fn only_a_tenant_token_makes_a_calendar_required_or_takes_the_flag_back() {
    let Setting {
        world,
        acme,
        anna,
        ben,
        carla,
        staff,
    } = setting().await;
    world.calendar(&acme, &anna, "projects", CalendarKind::User).await;
    let owner = world.api(&acme, &anna, &[Scope::CalendarsRead, Scope::CalendarsWrite]);
    let projects = (&anna, "projects");

    // The owner shares the calendar through the API like before, and cannot put it into the homes for good.
    let optional = put_as(&world, &owner, projects, &staff, GrantAccess::Read, false)
        .await
        .unwrap();
    assert!(!optional.value.required);
    let error = put_as(&world, &owner, projects, &carla, GrantAccess::Read, true)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    assert!(
        error.field_errors().iter().any(|field| field.pointer == "/required"),
        "{error:?}"
    );
    let error = put_as(&world, &owner, projects, &staff, GrantAccess::Read, true)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden, "not for a grant that exists either");
    home_of(&world, &acme, &ben).await;
    delete(&world, &acme, &ben, "projects").await.unwrap();
    assert_eq!(
        bindings(&world, &acme, &ben, Some(true)).await.len(),
        1,
        "ben could still hide it"
    );

    // The operator marks it; the owner's later `PUT`s (with or without the flag) neither set nor clear it.
    let marked = grant(&world, &acme, &anna, "projects", &staff, true).await;
    assert!(marked.required);
    let kept = put_as(&world, &owner, projects, &staff, GrantAccess::ReadWrite, false)
        .await
        .unwrap();
    assert!(kept.value.required, "a principal's PUT keeps the flag the grant has");
    assert_eq!(
        kept.value.access,
        GrantAccess::ReadWrite,
        "the access is the owner's to change"
    );
    let error = world
        .services
        .sharing
        .delete_grant(&owner, &world.key(&anna, "projects"), &staff.name, Conditions::none())
        .await
        .unwrap_err();
    assert_eq!(
        error.kind(),
        ErrorKind::Forbidden,
        "the owner cannot take a required grant back"
    );
    let listed = world
        .services
        .sharing
        .list_grants(&world.admin(&acme), &world.key(&anna, "projects"), PageRequest::first())
        .await
        .unwrap()
        .items;
    assert!(listed.iter().all(|grant| grant.required), "{listed:?}");

    // The operator takes it back, and then the owner may remove the grant.
    let optional = grant(&world, &acme, &anna, "projects", &staff, false).await;
    assert!(!optional.required);
    world
        .services
        .sharing
        .delete_grant(&owner, &world.key(&anna, "projects"), &staff.name, Conditions::none())
        .await
        .unwrap();
}

#[tokio::test]
async fn a_grant_of_a_group_to_its_own_calendar_adds_no_access_and_is_the_operators_alone() {
    let Setting {
        world,
        acme,
        ben,
        staff,
        ..
    } = setting().await;
    world.calendar(&acme, &staff, "board", CalendarKind::Group).await;
    let admin = world.admin(&acme);
    let board = (&staff, "board");

    // Its access is `read`, the floor of the grants: a higher level would raise every member above the group's default.
    for access in [GrantAccess::ReadWrite, GrantAccess::Admin] {
        let error = put_as(&world, &admin, board, &staff, access, true).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid, "{access:?}");
        assert!(
            error.field_errors().iter().any(|field| field.pointer == "/access"),
            "{error:?}"
        );
    }
    assert!(
        put_as(&world, &admin, board, &staff, GrantAccess::Read, true)
            .await
            .is_ok()
    );

    // A person who administers the calendar through the API cannot do it: the flag is the operator's.
    put_as(&world, &admin, board, &ben, GrantAccess::Admin, false)
        .await
        .unwrap();
    let administrator = world.api(&acme, &ben, &[Scope::CalendarsRead, Scope::CalendarsWrite]);
    let error = put_as(&world, &administrator, board, &staff, GrantAccess::Read, false)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    assert!(
        error.field_errors().iter().any(|field| field.pointer == "/grantee"),
        "{error:?}"
    );
}

#[tokio::test]
async fn taking_the_flag_off_a_groups_own_calendar_keeps_the_calendar_and_its_owner_binding() {
    let Setting {
        world,
        acme,
        ben,
        staff,
        ..
    } = setting().await;
    world.calendar(&acme, &staff, "board", CalendarKind::Group).await;
    home_of(&world, &acme, &ben).await;
    grant(&world, &acme, &staff, "board", &staff, true).await;
    let error = delete(&world, &acme, &ben, "board").await.unwrap_err();
    assert!(is_unbind_refusal(&error), "{error:?}");

    // Removing the grant makes the calendar optional again; it does not take the group's own binding along.
    world
        .services
        .sharing
        .delete_grant(
            &world.admin(&acme),
            &world.key(&staff, "board"),
            &staff.name,
            Conditions::none(),
        )
        .await
        .unwrap();
    assert!(
        bindings(&world, &acme, &staff, None)
            .await
            .iter()
            .any(|view| view.calendar.as_str() == "board"),
        "the owner binding of the group stays"
    );
    delete(&world, &acme, &ben, "board").await.unwrap();
    assert_eq!(
        bindings(&world, &acme, &ben, Some(true)).await.len(),
        1,
        "a member may hide it now"
    );
}
