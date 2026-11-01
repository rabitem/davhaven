//! Calendars: homes and lazy bindings, MKCALENDAR, PROPPATCH, deletion of bound collections, the special
//! collections of a home and the management API's calendar resources.

use davhaven_testkit::davhaven_app::services::{
    CalendarRef, CalendarSearch, CalendarSpec, Conditions, DeadProperty, GrantSpec, MergePatch, MkCalendar,
    PageRequest, PropPatch, PropertyChange, PropertyName, PropertyStatus, SharingRole,
};
use davhaven_testkit::davhaven_domain::{
    Access, CalendarKind, CalendarSlug, ComponentKind, ErrorKind, EventType, GrantAccess, Precondition, Privilege,
    ResourcePath, Scope, ScopeSet, Transparency,
};
use davhaven_testkit::davhaven_wire::{CalendarWrite, GrantWrite};
use serde_json::json;

use super::support::{Org, Person, World};

const BERLIN: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\n\
BEGIN:STANDARD\r\nDTSTART:19701025T030000\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\n\
RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU\r\nEND:STANDARD\r\nBEGIN:DAYLIGHT\r\nDTSTART:19700329T020000\r\n\
TZOFFSETFROM:+0100\r\nTZOFFSETTO:+0200\r\nRRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU\r\nEND:DAYLIGHT\r\n\
END:VTIMEZONE\r\nEND:VCALENDAR\r\n";

fn slug(text: &str) -> CalendarSlug {
    CalendarSlug::parse(text).unwrap()
}

fn mk(world: &World, org: &Org, owner: &Person, name: &str) -> MkCalendar {
    MkCalendar {
        path: world.collection(org, owner, name),
        display_name: None,
        description: None,
        color: None,
        sort_order: None,
        components: None,
        timezone_ics: None,
        schedule_transp: None,
        dead_properties: Vec::new(),
    }
}

async fn grant(world: &World, org: &Org, owner: &Person, calendar: &str, grantee: &Person, access: GrantAccess) {
    world
        .services
        .sharing
        .put_grant(
            &world.admin(org),
            GrantSpec {
                calendar: world.key(owner, calendar),
                grantee: grantee.name.clone(),
                body: GrantWrite {
                    access,
                    required: false,
                },
            },
            Conditions::none(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn a_home_lists_the_owned_calendars_and_binds_group_calendars_on_the_first_listing() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let team = world.group(&acme, "team", &[&anna]).await;
    let shared = world.calendar(&acme, &team, "shared", CalendarKind::Group).await;
    let dav = world.dav(&acme, &anna);

    let home = world.services.calendars.list_home(&dav, &anna.name).await.unwrap();
    let paths: Vec<String> = home.iter().map(|view| view.path.format()).collect();
    assert_eq!(paths.len(), 2, "{paths:?}");
    assert!(
        paths.contains(&"/dav/calendars/acme/anna/personal/".to_owned()),
        "{paths:?}"
    );
    assert!(
        paths.contains(&"/dav/calendars/acme/anna/shared/".to_owned()),
        "{paths:?}"
    );

    let personal = home.iter().find(|view| view.kind == CalendarKind::Personal).unwrap();
    assert_eq!(personal.access, Access::Owner);
    assert_eq!(personal.sharing, SharingRole::Unshared);
    assert!(personal.privileges.contains(Privilege::Share));
    assert!(personal.privileges.contains(Privilege::WriteContent));
    assert_eq!(personal.owner.name, anna.name);
    assert_eq!(personal.components, ComponentKind::ALL.to_vec());

    let group = home.iter().find(|view| view.kind == CalendarKind::Group).unwrap();
    assert_eq!(group.calendar_id, shared.id);
    assert_eq!(group.owner.name, team.name, "the group owns the calendar");
    assert_eq!(
        group.access,
        Access::ReadWrite,
        "members get the tenant's group default access"
    );
    assert!(group.privileges.contains(Privilege::WriteContent));
    assert!(!group.privileges.contains(Privilege::Share));

    // The bindings exist now: a second listing shows the same ones and creates no more.
    let again = world.services.calendars.list_home(&dav, &anna.name).await.unwrap();
    let mut ids: Vec<_> = home.iter().map(|view| view.binding_id).collect();
    let mut ids_again: Vec<_> = again.iter().map(|view| view.binding_id).collect();
    ids.sort();
    ids_again.sort();
    assert_eq!(ids, ids_again);

    // Someone outside the group sees only the own calendar, and nobody lists other people's homes.
    let bens = world
        .services
        .calendars
        .list_home(&world.dav(&acme, &ben), &ben.name)
        .await
        .unwrap();
    assert_eq!(bens.len(), 1);
    assert_eq!(
        world
            .services
            .calendars
            .list_home(&world.dav(&acme, &ben), &anna.name)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );

    // Leaving the group ends the access, and the calendar disappears from the listing.
    world
        .services
        .principals
        .remove_member(&world.admin(&acme), &team.name, &anna.name)
        .await
        .unwrap();
    let after = world.services.calendars.list_home(&dav, &anna.name).await.unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].kind, CalendarKind::Personal);
}

#[tokio::test]
async fn binding_slugs_avoid_the_slugs_a_home_uses_already() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let team = world.group(&acme, "team", &[&anna]).await;
    world.calendar(&acme, &anna, "shared", CalendarKind::User).await;
    world.calendar(&acme, &team, "shared", CalendarKind::Group).await;

    let home = world
        .services
        .calendars
        .list_home(&world.dav(&acme, &anna), &anna.name)
        .await
        .unwrap();
    let mut paths: Vec<String> = home.iter().map(|view| view.path.format()).collect();
    paths.sort();
    assert_eq!(
        paths,
        vec![
            "/dav/calendars/acme/anna/personal/".to_owned(),
            "/dav/calendars/acme/anna/shared-2/".to_owned(),
            "/dav/calendars/acme/anna/shared/".to_owned(),
        ]
    );
    let group = home.iter().find(|view| view.kind == CalendarKind::Group).unwrap();
    assert_eq!(group.path.format(), "/dav/calendars/acme/anna/shared-2/");
    let own = home.iter().find(|view| view.kind == CalendarKind::User).unwrap();
    assert_eq!(
        own.path.format(),
        "/dav/calendars/acme/anna/shared/",
        "the owned calendar keeps its slug"
    );
}

#[tokio::test]
async fn managed_calendars_are_read_only_on_dav_and_visible_to_their_grantees() {
    let world = World::new();
    let acme = world.org("acme").await;
    let svc = world
        .principal(
            &acme,
            "svc",
            davhaven_testkit::davhaven_domain::PrincipalKind::Service,
        )
        .await;
    let anna = world.user(&acme, "anna").await;
    let managed = world.calendar(&acme, &svc, "holidays", CalendarKind::Managed).await;
    assert_eq!(managed.kind, CalendarKind::Managed);
    grant(&world, &acme, &svc, "holidays", &anna, GrantAccess::Read).await;

    let home = world
        .services
        .calendars
        .list_home(&world.dav(&acme, &anna), &anna.name)
        .await
        .unwrap();
    let view = home
        .iter()
        .find(|view| view.calendar_id == managed.id)
        .expect("bound lazily on the listing");
    assert_eq!(view.access, Access::Read);
    assert!(!view.privileges.contains(Privilege::WriteContent));
    assert!(view.privileges.contains(Privilege::Read));
    assert_eq!(view.sharing, SharingRole::Sharee);

    // Even the owner's DAV privileges are capped at read: writes go through the API.
    let owners = world
        .services
        .calendars
        .list_home(&world.dav(&acme, &svc), &svc.name)
        .await
        .unwrap();
    let own = owners.iter().find(|view| view.calendar_id == managed.id).unwrap();
    assert_eq!(own.access, Access::Owner);
    assert!(!own.privileges.contains(Privilege::WriteContent));
    assert!(!own.privileges.contains(Privilege::Bind));
}

#[tokio::test]
async fn mkcalendar_creates_a_user_calendar_in_the_callers_home() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let dav = world.dav(&acme, &anna);
    let request = MkCalendar {
        display_name: Some("  Projects ".to_owned()),
        description: Some("Everything we plan".to_owned()),
        color: Some("#ff0000".to_owned()),
        sort_order: Some(5),
        components: Some(vec![ComponentKind::Event]),
        timezone_ics: Some(BERLIN.to_owned()),
        schedule_transp: Some(Transparency::Transparent),
        dead_properties: vec![DeadProperty {
            name: PropertyName::new("urn:example", "note"),
            value_xml: "<note>hello</note>".to_owned(),
        }],
        ..mk(&world, &acme, &anna, "projects")
    };
    let created = world
        .services
        .calendars
        .mkcalendar(&dav, request.clone())
        .await
        .unwrap();
    assert_eq!(created.kind, CalendarKind::User);
    assert_eq!(created.display_name, "Projects");
    assert_eq!(created.color.as_deref(), Some("#FF0000"), "colors are normalized");
    assert_eq!(created.sort_order, 5);
    assert_eq!(created.components, vec![ComponentKind::Event]);
    assert_eq!(created.schedule_transp, Transparency::Transparent);
    assert_eq!(created.access, Access::Owner);
    assert_eq!(created.path.format(), "/dav/calendars/acme/anna/projects/");
    assert!(created.timezone_ics.is_some());

    let collection = world
        .services
        .calendars
        .get_collection(&dav, &created.path)
        .await
        .unwrap();
    assert_eq!(collection.dead_properties.len(), 1);
    assert_eq!(collection.dead_properties[0].value_xml, "<note>hello</note>");
    assert_eq!(collection.display_name, "Projects");
    assert_eq!(
        world.events_of(&acme, EventType::CalendarCreated).await.len(),
        3,
        "two personal calendars and projects"
    );

    // The slug is taken: the owner's own calendar and any binding count.
    for taken in ["projects", "personal"] {
        let error = world
            .services
            .calendars
            .mkcalendar(&dav, mk(&world, &acme, &anna, taken))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Conflict, "{taken}");
        assert_eq!(error.precondition(), Some(&Precondition::ResourceMustBeNull), "{taken}");
    }
    // Other people's homes are not there to create calendars in.
    let foreign = world
        .services
        .calendars
        .mkcalendar(&world.dav(&acme, &ben), mk(&world, &acme, &anna, "intruder"))
        .await
        .unwrap_err();
    assert_eq!(foreign.kind(), ErrorKind::NotFound);
}

#[tokio::test]
async fn mkcalendar_rejects_what_the_calendar_cannot_hold_and_stores_nothing() {
    let world = World::new();
    let acme = world
        .org_with("acme", |settings| {
            settings.allowed_components = vec![ComponentKind::Event];
        })
        .await;
    let anna = world.user(&acme, "anna").await;
    let dav = world.dav(&acme, &anna);
    let attempts = [
        (
            "bad-color",
            MkCalendar {
                color: Some("red".to_owned()),
                ..mk(&world, &acme, &anna, "bad-color")
            },
            None,
        ),
        (
            "no-components",
            MkCalendar {
                components: Some(Vec::new()),
                ..mk(&world, &acme, &anna, "no-components")
            },
            Some("supported-calendar-component"),
        ),
        (
            "todos",
            MkCalendar {
                components: Some(vec![ComponentKind::Todo]),
                ..mk(&world, &acme, &anna, "todos")
            },
            Some("supported-calendar-component"),
        ),
        (
            "bad-zone",
            MkCalendar {
                timezone_ics: Some("not a calendar".to_owned()),
                ..mk(&world, &acme, &anna, "bad-zone")
            },
            Some("valid-calendar-data"),
        ),
        (
            "blank-name",
            MkCalendar {
                display_name: Some("   ".to_owned()),
                ..mk(&world, &acme, &anna, "blank-name")
            },
            None,
        ),
        (
            "large-property",
            MkCalendar {
                dead_properties: vec![DeadProperty {
                    name: PropertyName::new("urn:example", "big"),
                    value_xml: "x".repeat(5000),
                }],
                ..mk(&world, &acme, &anna, "large-property")
            },
            None,
        ),
    ];
    for (name, request, precondition) in attempts {
        let error = world.services.calendars.mkcalendar(&dav, request).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid, "{name}");
        assert_eq!(error.precondition().map(Precondition::code), precondition, "{name}");
    }
    let home = world.services.calendars.list_home(&dav, &anna.name).await.unwrap();
    assert_eq!(home.len(), 1, "only the personal calendar exists");
}

#[tokio::test]
async fn proppatch_changes_binding_properties_for_the_binding_and_shared_ones_for_everyone_atomically() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    grant(&world, &acme, &anna, "work", &ben, GrantAccess::Read).await;
    let annas = world.dav(&acme, &anna);
    let bens = world.dav(&acme, &ben);
    let work = world.collection(&acme, &anna, "work");
    let bens_work = world
        .services
        .calendars
        .list_home(&bens, &ben.name)
        .await
        .unwrap()
        .into_iter()
        .find(|view| view.kind == CalendarKind::User)
        .expect("the share is bound on the first listing")
        .path;

    // The owner may change everything; all properties apply or none.
    let before = world.services.calendars.get_collection(&annas, &work).await.unwrap();
    let outcome = world
        .services
        .calendars
        .proppatch(
            &annas,
            &work,
            PropPatch {
                changes: vec![
                    PropertyChange::DisplayName(Some("Work stuff".to_owned())),
                    PropertyChange::Description(Some("Meetings".to_owned())),
                    PropertyChange::Color(Some("#00ff00".to_owned())),
                    PropertyChange::Order(Some(9)),
                    PropertyChange::Timezone(Some(BERLIN.to_owned())),
                    PropertyChange::ScheduleTransparency(Some(Transparency::Transparent)),
                    PropertyChange::Dead {
                        name: PropertyName::new("urn:example", "note"),
                        value_xml: Some("<note>x</note>".to_owned()),
                    },
                ],
            },
        )
        .await
        .unwrap();
    assert!(outcome.is_applied(), "{outcome:?}");
    assert_eq!(outcome.results.len(), 7);
    let after = world.services.calendars.get_collection(&annas, &work).await.unwrap();
    let calendar = after.calendar.as_ref().unwrap();
    assert_eq!(calendar.display_name, "Work stuff");
    assert_eq!(calendar.description.as_deref(), Some("Meetings"));
    assert_eq!(calendar.color.as_deref(), Some("#00FF00"));
    assert_eq!(calendar.sort_order, 9);
    assert!(calendar.timezone_ics.is_some());
    assert_eq!(calendar.schedule_transp, Transparency::Transparent);
    assert_ne!(
        after.sync_token, before.sync_token,
        "the CTag moves so that the principal's other clients refresh"
    );
    assert_eq!(after.dead_properties.len(), 1);

    // The sharee's per-binding changes are theirs alone.
    let outcome = world
        .services
        .calendars
        .proppatch(
            &bens,
            &bens_work,
            PropPatch {
                changes: vec![
                    PropertyChange::DisplayName(Some("Anna's work".to_owned())),
                    PropertyChange::Color(Some("#0000ff".to_owned())),
                ],
            },
        )
        .await
        .unwrap();
    assert!(outcome.is_applied());
    let owners_view = world.services.calendars.get_collection(&annas, &work).await.unwrap();
    assert_eq!(owners_view.display_name, "Work stuff", "the owner's view is unchanged");
    let bens_view = world
        .services
        .calendars
        .get_collection(&bens, &bens_work)
        .await
        .unwrap();
    assert_eq!(bens_view.display_name, "Anna's work");
    assert_eq!(bens_view.calendar.as_ref().unwrap().color.as_deref(), Some("#0000FF"));

    // A read-only sharee cannot change the shared description: nothing is applied, the rest reports 424.
    let outcome = world
        .services
        .calendars
        .proppatch(
            &bens,
            &bens_work,
            PropPatch {
                changes: vec![
                    PropertyChange::DisplayName(Some("Should not stick".to_owned())),
                    PropertyChange::Description(Some("Hijacked".to_owned())),
                ],
            },
        )
        .await
        .unwrap();
    assert!(!outcome.is_applied());
    let statuses: Vec<PropertyStatus> = outcome.results.iter().map(|result| result.status).collect();
    assert_eq!(
        statuses,
        vec![PropertyStatus::FailedDependency, PropertyStatus::Forbidden]
    );
    let bens_view = world
        .services
        .calendars
        .get_collection(&bens, &bens_work)
        .await
        .unwrap();
    assert_eq!(bens_view.display_name, "Anna's work");
    assert_eq!(
        world
            .services
            .calendars
            .get_collection(&annas, &work)
            .await
            .unwrap()
            .calendar
            .unwrap()
            .description
            .as_deref(),
        Some("Meetings")
    );
}

#[tokio::test]
async fn proppatch_refuses_unusable_values_and_properties_beyond_the_limits() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let dav = world.dav(&acme, &anna);
    let personal = world.collection(&acme, &anna, "personal");
    let patch = |changes| {
        world
            .services
            .calendars
            .proppatch(&dav, &personal, PropPatch { changes })
    };

    let outcome = patch(vec![
        PropertyChange::Color(Some("not-a-color".to_owned())),
        PropertyChange::Timezone(Some("garbage".to_owned())),
        PropertyChange::DisplayName(Some("fine".to_owned())),
    ])
    .await
    .unwrap();
    let statuses: Vec<PropertyStatus> = outcome.results.iter().map(|result| result.status).collect();
    assert_eq!(
        statuses,
        vec![
            PropertyStatus::Conflict,
            PropertyStatus::Conflict,
            PropertyStatus::FailedDependency
        ]
    );
    // A time zone that is no VTIMEZONE says which precondition it breaks (RFC 4791 section 5.2.2): the status alone
    // would not tell a color that is no color from it. The property that was fine and depends on them says nothing.
    let preconditions: Vec<Option<&Precondition>> = outcome
        .results
        .iter()
        .map(|result| result.precondition.as_ref())
        .collect();
    assert!(
        matches!(
            preconditions.as_slice(),
            [None, Some(Precondition::ValidCalendarData(reason)), None] if !reason.is_empty()
        ),
        "{preconditions:?}"
    );

    let big = patch(vec![PropertyChange::Dead {
        name: PropertyName::new("urn:example", "big"),
        value_xml: Some("x".repeat(5000)),
    }])
    .await
    .unwrap();
    assert_eq!(big.results[0].status, PropertyStatus::InsufficientStorage);

    let mut many = Vec::new();
    for index in 0..51 {
        many.push(PropertyChange::Dead {
            name: PropertyName::new("urn:example", &format!("p{index}")),
            value_xml: Some("<v/>".to_owned()),
        });
    }
    let outcome = patch(many).await.unwrap();
    assert_eq!(
        outcome.results.last().map(|result| result.status),
        Some(PropertyStatus::InsufficientStorage)
    );
    assert!(
        world
            .services
            .calendars
            .get_collection(&dav, &personal)
            .await
            .unwrap()
            .dead_properties
            .is_empty(),
        "an atomic patch that failed left nothing behind"
    );

    // Properties can be removed again.
    let name = PropertyName::new("urn:example", "note");
    patch(vec![PropertyChange::Dead {
        name: name.clone(),
        value_xml: Some("<note/>".to_owned()),
    }])
    .await
    .unwrap();
    assert_eq!(
        world
            .services
            .calendars
            .get_collection(&dav, &personal)
            .await
            .unwrap()
            .dead_properties
            .len(),
        1
    );
    patch(vec![PropertyChange::Dead { name, value_xml: None }])
        .await
        .unwrap();
    assert!(
        world
            .services
            .calendars
            .get_collection(&dav, &personal)
            .await
            .unwrap()
            .dead_properties
            .is_empty()
    );

    // Other people's collections are invisible.
    let ben = world.user(&acme, "ben").await;
    let error = world
        .services
        .calendars
        .proppatch(&world.dav(&acme, &ben), &personal, PropPatch::default())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound);
}

#[tokio::test]
async fn deleting_a_bound_collection_depends_on_who_deletes_it() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let team = world.group(&acme, "team", &[&anna, &ben]).await;
    let group_calendar = world.calendar(&acme, &team, "shared", CalendarKind::Group).await;
    world.calendar(&acme, &anna, "temp", CalendarKind::User).await;
    let annas = world.dav(&acme, &anna);
    let bens = world.dav(&acme, &ben);
    world.services.calendars.list_home(&annas, &anna.name).await.unwrap();
    world.services.calendars.list_home(&bens, &ben.name).await.unwrap();

    // A member removes a group calendar from their own home only.
    let annas_object = world.object(&acme, &anna, "shared", "g.ics");
    let bens_object = world.object(&acme, &ben, "shared", "g.ics");
    world
        .services
        .objects
        .put(
            &annas,
            davhaven_testkit::davhaven_app::services::PutRequest {
                path: annas_object.clone(),
                body: super::support::ics("g-1", "Group event"),
                content_type: None,
                preconditions: davhaven_testkit::davhaven_app::services::WritePrecondition::none(),
                schedule_reply: davhaven_testkit::davhaven_app::services::ScheduleReply::Send,
            },
        )
        .await
        .unwrap();
    assert!(
        world.services.objects.get(&bens, &bens_object).await.is_ok(),
        "visible before"
    );
    world
        .services
        .calendars
        .delete_collection(&bens, &world.collection(&acme, &ben, "shared"), Conditions::none())
        .await
        .unwrap();
    assert_eq!(
        world
            .services
            .calendars
            .get_collection(&bens, &world.collection(&acme, &ben, "shared"))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound,
        "a hidden binding does not resolve over DAV"
    );
    assert_eq!(
        world
            .services
            .objects
            .get(&bens, &bens_object)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    assert!(
        world.services.objects.get(&annas, &annas_object).await.is_ok(),
        "anna's view is untouched"
    );
    let bens_home = world.services.calendars.list_home(&bens, &ben.name).await.unwrap();
    assert!(
        bens_home.iter().all(|view| view.calendar_id != group_calendar.id),
        "hidden for ben"
    );
    let annas_home = world.services.calendars.list_home(&annas, &anna.name).await.unwrap();
    assert!(
        annas_home.iter().any(|view| view.calendar_id == group_calendar.id),
        "anna still has it"
    );
    assert!(
        world
            .services
            .calendars
            .get(&world.admin(&acme), &CalendarRef::Id(group_calendar.id))
            .await
            .is_ok(),
        "the calendar itself is untouched"
    );
    assert_eq!(
        world.events_of(&acme, EventType::CalendarDeleted).await.len(),
        0,
        "hiding a binding is not a deletion"
    );

    // The owner deletes for everyone; a stale version is refused.
    let temp = world.collection(&acme, &anna, "temp");
    let current = world
        .services
        .calendars
        .get(&world.admin(&acme), &world.key(&anna, "temp"))
        .await
        .unwrap();
    let error = world
        .services
        .calendars
        .delete_collection(&annas, &temp, Conditions::if_match(current.version + 1))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PreconditionFailed);
    world
        .services
        .calendars
        .delete_collection(&annas, &temp, Conditions::if_match(current.version))
        .await
        .unwrap();
    assert_eq!(
        world
            .services
            .calendars
            .get_collection(&annas, &temp)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        world
            .services
            .calendars
            .get(&world.admin(&acme), &CalendarRef::Id(current.id))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    assert_eq!(world.events_of(&acme, EventType::CalendarDeleted).await.len(), 1);
    // The slug of the deleted calendar can be used again.
    assert!(
        world
            .services
            .calendars
            .mkcalendar(&annas, mk(&world, &acme, &anna, "temp"))
            .await
            .is_ok()
    );

    // Anything that is not a collection of the home answers not found.
    let object = world.object(&acme, &anna, "personal", "x.ics");
    assert_eq!(
        world
            .services
            .calendars
            .delete_collection(&annas, &object, Conditions::none())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
}

#[tokio::test]
async fn the_special_collections_of_a_home_are_readable_by_their_owner_only() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let dav = world.dav(&acme, &anna);
    let paths = |who: &Person| {
        [
            ResourcePath::Home {
                tenant: acme.slug.clone(),
                principal: who.name.clone(),
            },
            ResourcePath::Inbox {
                tenant: acme.slug.clone(),
                principal: who.name.clone(),
            },
            ResourcePath::Outbox {
                tenant: acme.slug.clone(),
                principal: who.name.clone(),
            },
            ResourcePath::Notifications {
                tenant: acme.slug.clone(),
                principal: who.name.clone(),
            },
        ]
    };
    let [home, inbox, outbox, notifications] = paths(&anna);
    for (path, tokens, privilege) in [
        (&home, false, Privilege::Bind),
        (&inbox, true, Privilege::ScheduleDeliver),
        (&outbox, false, Privilege::ScheduleSend),
        (&notifications, true, Privilege::Unbind),
    ] {
        let view = world.services.calendars.get_collection(&dav, path).await.unwrap();
        assert_eq!(view.path, *path);
        assert_eq!(view.sync_token.is_some(), tokens, "{path}");
        assert!(view.privileges.contains(privilege), "{path}");
        assert!(view.calendar.is_none());
    }
    for path in paths(&anna) {
        assert_eq!(
            world
                .services
                .calendars
                .get_collection(&world.dav(&acme, &ben), &path)
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::NotFound,
            "{path}"
        );
    }
    // Principal resources are not collections of a home.
    let principal = ResourcePath::Principal {
        tenant: acme.slug.clone(),
        principal: anna.name.clone(),
    };
    assert_eq!(
        world
            .services
            .calendars
            .get_collection(&dav, &principal)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
}

#[tokio::test]
async fn the_management_api_creates_reads_replaces_patches_and_deletes_calendars() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let admin = world.admin(&acme);
    let created = world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    assert_eq!(created.version, 1);
    assert_eq!(created.owner, anna.name);
    assert!(created.dav_url.as_str().ends_with("/dav/calendars/acme/anna/work/"));

    let by_key = world
        .services
        .calendars
        .get(&admin, &world.key(&anna, "work"))
        .await
        .unwrap();
    let by_id = world
        .services
        .calendars
        .get(&admin, &CalendarRef::Id(created.id))
        .await
        .unwrap();
    assert_eq!(by_key, by_id);
    assert_eq!(by_key, created);

    // The same body twice changes nothing; a change is a new version and an event.
    let spec = |name: &str, extra: CalendarWrite| CalendarSpec {
        owner: anna.name.clone(),
        slug: slug(name),
        body: extra,
    };
    let body = CalendarWrite {
        kind: Some(CalendarKind::User),
        display_name: "work calendar".to_owned(),
        description: None,
        color: None,
        sort_order: None,
        components: None,
    };
    let events = world.events_of(&acme, EventType::CalendarCreated).await.len();
    let again = world
        .services
        .calendars
        .upsert(&admin, spec("work", body.clone()), Conditions::none())
        .await
        .unwrap();
    assert!(!again.created);
    assert_eq!(again.value, created);
    assert_eq!(world.events_of(&acme, EventType::CalendarCreated).await.len(), events);
    assert!(world.events_of(&acme, EventType::CalendarUpdated).await.is_empty());

    let renamed = world
        .services
        .calendars
        .upsert(
            &admin,
            spec(
                "work",
                CalendarWrite {
                    display_name: "Renamed".to_owned(),
                    color: Some("#336699".to_owned()),
                    sort_order: Some(3),
                    ..body.clone()
                },
            ),
            Conditions::if_match(1),
        )
        .await
        .unwrap();
    assert_eq!(renamed.value.version, 2);
    assert_eq!(renamed.value.display_name, "Renamed");
    assert_eq!(renamed.value.color.as_deref(), Some("#336699"));
    assert_eq!(world.events_of(&acme, EventType::CalendarUpdated).await.len(), 1);
    assert_eq!(
        world
            .services
            .calendars
            .upsert(&admin, spec("work", body.clone()), Conditions::if_match(1))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PreconditionFailed
    );
    assert_eq!(
        world
            .services
            .calendars
            .upsert(&admin, spec("work", body.clone()), Conditions::create_only())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PreconditionFailed
    );

    // A merge patch changes members and leaves the rest.
    let patched = world
        .services
        .calendars
        .patch(
            &admin,
            &world.key(&anna, "work"),
            MergePatch::new(json!({"description": "Meetings", "color": null})).unwrap(),
            Conditions::if_match(2),
        )
        .await
        .unwrap();
    assert_eq!(patched.description.as_deref(), Some("Meetings"));
    assert_eq!(patched.color, None);
    assert_eq!(patched.display_name, "Renamed");
    assert_eq!(patched.version, 3);

    // Kinds are fixed, personal and mirror calendars are not created here, groups own group calendars only.
    let kind = world
        .services
        .calendars
        .upsert(
            &admin,
            spec(
                "work",
                CalendarWrite {
                    kind: Some(CalendarKind::Managed),
                    ..body.clone()
                },
            ),
            Conditions::none(),
        )
        .await
        .unwrap_err();
    assert_eq!(kind.field_errors().first().map(|field| field.code), Some("immutable"));
    for forbidden in [CalendarKind::Personal, CalendarKind::Mirror] {
        let error = world
            .services
            .calendars
            .upsert(
                &admin,
                spec(
                    "other",
                    CalendarWrite {
                        kind: Some(forbidden),
                        ..body.clone()
                    },
                ),
                Conditions::none(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.field_errors().first().map(|field| field.code),
            Some("not-allowed"),
            "{forbidden:?}"
        );
    }
    let mismatch = world
        .services
        .calendars
        .upsert(
            &admin,
            spec(
                "grp",
                CalendarWrite {
                    kind: Some(CalendarKind::Group),
                    ..body.clone()
                },
            ),
            Conditions::none(),
        )
        .await
        .unwrap_err();
    assert_eq!(
        mismatch.field_errors().first().map(|field| field.code),
        Some("owner-mismatch")
    );

    // Deleting needs the version.
    assert_eq!(
        world
            .services
            .calendars
            .delete(&admin, &world.key(&anna, "work"), Conditions::none())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PreconditionRequired
    );
    assert_eq!(
        world
            .services
            .calendars
            .delete(&admin, &world.key(&anna, "work"), Conditions::if_match(1))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PreconditionFailed
    );
    world
        .services
        .calendars
        .delete(&admin, &world.key(&anna, "work"), Conditions::if_match(3))
        .await
        .unwrap();
    assert_eq!(
        world
            .services
            .calendars
            .get(&admin, &world.key(&anna, "work"))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    assert_eq!(world.events_of(&acme, EventType::CalendarDeleted).await.len(), 1);
}

#[tokio::test]
async fn calendar_administration_needs_its_scopes_and_principal_tokens_reach_their_own_calendars_only() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    let body = CalendarWrite {
        kind: None,
        display_name: "Mine".to_owned(),
        description: None,
        color: None,
        sort_order: None,
        components: None,
    };
    let spec = |owner: &Person| CalendarSpec {
        owner: owner.name.clone(),
        slug: slug("mine"),
        body: body.clone(),
    };

    // Tenant tokens: reading needs calendars:read, writing calendars:write.
    let reader = world.tenant_token(&acme, ScopeSet::of(&[Scope::CalendarsRead]));
    assert!(
        world
            .services
            .calendars
            .get(&reader, &world.key(&anna, "work"))
            .await
            .is_ok()
    );
    assert_eq!(
        world
            .services
            .calendars
            .upsert(&reader, spec(&anna), Conditions::none())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );
    let scopeless = world.tenant_token(&acme, ScopeSet::empty());
    assert_eq!(
        world
            .services
            .calendars
            .get(&scopeless, &world.key(&anna, "work"))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );

    // A principal token manages its own calendars; other principals' calendars do not exist for it.
    let writer = world.api(&acme, &anna, &[Scope::CalendarsRead, Scope::CalendarsWrite]);
    assert!(
        world
            .services
            .calendars
            .upsert(&writer, spec(&anna), Conditions::none())
            .await
            .unwrap()
            .created
    );
    assert_eq!(
        world
            .services
            .calendars
            .upsert(&writer, spec(&ben), Conditions::none())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    let bens = world.api(&acme, &ben, &[Scope::CalendarsRead, Scope::CalendarsWrite]);
    assert_eq!(
        world
            .services
            .calendars
            .get(&bens, &world.key(&anna, "work"))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
}

#[tokio::test]
async fn calendars_are_listed_per_owner_and_searched_per_tenant() {
    let world = World::new();
    let acme = world.org("acme").await;
    let other = world.org("other").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let svc = world
        .principal(
            &acme,
            "svc",
            davhaven_testkit::davhaven_domain::PrincipalKind::Service,
        )
        .await;
    for index in 0..4 {
        world
            .calendar(&acme, &anna, &format!("cal-{index}"), CalendarKind::User)
            .await;
    }
    world.calendar(&acme, &svc, "holidays", CalendarKind::Managed).await;
    let olga = world.user(&other, "olga").await;
    world.calendar(&other, &olga, "cal-0", CalendarKind::User).await;
    let admin = world.admin(&acme);

    let mut seen = Vec::new();
    let mut page = PageRequest::with_limit(2);
    loop {
        let batch = world
            .services
            .calendars
            .list_owned(&admin, &anna.name, page.clone())
            .await
            .unwrap();
        assert!(batch.items.len() <= 2);
        seen.extend(batch.items.iter().map(|view| view.slug.as_str().to_owned()));
        match batch.next_cursor {
            Some(cursor) => page = PageRequest::with_limit(2).after(cursor),
            None => break,
        }
    }
    assert_eq!(
        seen,
        vec!["personal", "cal-0", "cal-1", "cal-2", "cal-3"],
        "in creation order"
    );
    let bens_calendars = world
        .services
        .calendars
        .list_owned(&admin, &ben.name, PageRequest::first())
        .await
        .unwrap();
    assert_eq!(bens_calendars.items.len(), 1);

    let managed = world
        .services
        .calendars
        .list_tenant(
            &admin,
            CalendarSearch {
                kind: Some(CalendarKind::Managed),
                ..CalendarSearch::default()
            },
            PageRequest::first(),
        )
        .await
        .unwrap();
    assert_eq!(managed.items.len(), 1);
    assert_eq!(managed.items[0].slug.as_str(), "holidays");
    let by_text = world
        .services
        .calendars
        .list_tenant(
            &admin,
            CalendarSearch {
                query: Some("CAL-1".to_owned()),
                owner: Some(anna.name.clone()),
                ..CalendarSearch::default()
            },
            PageRequest::first(),
        )
        .await
        .unwrap();
    assert_eq!(
        by_text.items.len(),
        1,
        "case-insensitive text, own tenant only: {by_text:?}"
    );
    assert_eq!(by_text.items[0].slug.as_str(), "cal-1");
    let all = world
        .services
        .calendars
        .list_tenant(&admin, CalendarSearch::default(), PageRequest::first())
        .await
        .unwrap();
    assert_eq!(
        all.items.len(),
        7,
        "two personal calendars, four of anna's, the managed one, no foreign calendar"
    );
    assert_eq!(
        world
            .services
            .calendars
            .list_tenant(
                &world.dav(&acme, &anna),
                CalendarSearch::default(),
                PageRequest::first()
            )
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );
}

#[tokio::test]
async fn a_stranger_learns_nothing_about_calendars_from_conditions_kinds_or_patches() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    let bens = world.api(&acme, &ben, &[Scope::CalendarsRead, Scope::CalendarsWrite]);
    let state = || async {
        let view = world
            .services
            .calendars
            .get(&world.admin(&acme), &world.key(&anna, "work"))
            .await
            .unwrap();
        (
            view.sync_token.seq,
            view.version,
            world.audit(&acme).await.len(),
            world.events(&acme).await.len(),
        )
    };
    let before = state().await;
    let body = |kind: Option<CalendarKind>| CalendarWrite {
        kind,
        display_name: "Mine".to_owned(),
        description: None,
        color: None,
        sort_order: None,
        components: None,
    };

    // A PUT into Anna's home: the existing calendar and a missing one answer the same, whatever the conditions say
    // and whatever the body claims.
    for slug_text in ["work", "ghost"] {
        for conditions in [Conditions::none(), Conditions::create_only(), Conditions::if_match(99)] {
            for kind in [None, Some(CalendarKind::Managed), Some(CalendarKind::Personal)] {
                let error = world
                    .services
                    .calendars
                    .upsert(
                        &bens,
                        CalendarSpec {
                            owner: anna.name.clone(),
                            slug: slug(slug_text),
                            body: body(kind),
                        },
                        conditions,
                    )
                    .await
                    .unwrap_err();
                assert_eq!(error.kind(), ErrorKind::NotFound, "{slug_text} {conditions:?} {kind:?}");
            }
        }
    }
    // The same for PATCH and DELETE. A DELETE without If-Match may be told that it must be conditional, but then so is
    // one of a calendar that does not exist: the answer never tells the two apart.
    let mut unconditional_deletes = Vec::new();
    for slug_text in ["work", "ghost"] {
        let reference = world.key(&anna, slug_text);
        for conditions in [Conditions::none(), Conditions::if_match(99)] {
            let error = world
                .services
                .calendars
                .patch(
                    &bens,
                    &reference,
                    MergePatch::new(json!({"display_name": "Taken over"})).unwrap(),
                    conditions,
                )
                .await
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::NotFound, "patch {slug_text} {conditions:?}");
            let error = world
                .services
                .calendars
                .delete(&bens, &reference, conditions)
                .await
                .unwrap_err();
            if conditions == Conditions::none() {
                unconditional_deletes.push(error.kind());
            } else {
                assert_eq!(error.kind(), ErrorKind::NotFound, "delete {slug_text} {conditions:?}");
            }
        }
    }
    assert!(
        matches!(
            unconditional_deletes.as_slice(),
            [ErrorKind::NotFound | ErrorKind::PreconditionRequired, second] if *second == unconditional_deletes[0]
        ),
        "{unconditional_deletes:?}"
    );
    assert_eq!(state().await, before, "nothing changed");
}

#[tokio::test]
async fn shared_properties_set_by_proppatch_are_announced_and_a_display_name_is_stored_as_it_was_checked() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let dav = world.dav(&acme, &anna);
    let personal = world.collection(&acme, &anna, "personal");
    let announced = || async { world.events_of(&acme, EventType::CalendarUpdated).await.len() };
    let before = announced().await;

    // A per-binding property is the principal's own business and is not announced.
    world
        .services
        .calendars
        .proppatch(
            &dav,
            &personal,
            PropPatch {
                changes: vec![PropertyChange::DisplayName(Some("  Mine  ".to_owned()))],
            },
        )
        .await
        .unwrap();
    assert_eq!(announced().await, before);
    let view = world.services.calendars.get_collection(&dav, &personal).await.unwrap();
    assert_eq!(
        view.display_name, "Mine",
        "the trimmed name that was validated is the one that is stored"
    );

    // The description belongs to the calendar: webhook consumers learn of the change as they do for the API's.
    world
        .services
        .calendars
        .proppatch(
            &dav,
            &personal,
            PropPatch {
                changes: vec![PropertyChange::Description(Some("Everything".to_owned()))],
            },
        )
        .await
        .unwrap();
    assert_eq!(announced().await, before + 1);
}

#[tokio::test]
async fn dead_properties_count_their_names_against_the_size_limit() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let dav = world.dav(&acme, &anna);
    let personal = world.collection(&acme, &anna, "personal");
    let limit = usize::try_from(world.core.deps().limits.dav.max_dead_property_size).unwrap();
    let outcome = world
        .services
        .calendars
        .proppatch(
            &dav,
            &personal,
            PropPatch {
                changes: vec![PropertyChange::Dead {
                    name: PropertyName::new("urn:x", &"n".repeat(limit)),
                    value_xml: Some("v".to_owned()),
                }],
            },
        )
        .await
        .unwrap();
    assert_eq!(
        outcome.results[0].status,
        PropertyStatus::InsufficientStorage,
        "a name as long as the limit is too much with any value"
    );
    let fits = world
        .services
        .calendars
        .proppatch(
            &dav,
            &personal,
            PropPatch {
                changes: vec![PropertyChange::Dead {
                    name: PropertyName::new("urn:x", "short"),
                    value_xml: Some("v".repeat(limit - 20)),
                }],
            },
        )
        .await
        .unwrap();
    assert_eq!(fits.results[0].status, PropertyStatus::Applied);
}
