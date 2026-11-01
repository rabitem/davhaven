//! Reads that load many things at once cost a fixed number of queries, whatever the number (`ENGINEERING_RULES` R14,
//! backlog item 10): the collections of a calendar home with their owners, bindings, properties, grants and grantees,
//! and the principals of an `expand-property`. The answers are what the reads of one thing at a time answer; the cost
//! is read from the port calls (`PortCalls`), which is the only thing that tells a query per item from a query.

use std::collections::BTreeMap;

use davhaven_testkit::davhaven_app::services::{
    Conditions, DeadProperty, DeleteOptions, EventWrite, GrantSpec, HomeDetail, MkCalendar, PropertyName,
};
use davhaven_testkit::davhaven_domain::{
    CalendarKind, CalendarUserAddress, Email, ErrorKind, EventAttendee, EventData, EventOrganizer, EventTime,
    GrantAccess, PrincipalKind, ResourcePath, Scope, TenantSlug, Uid,
};
use davhaven_testkit::davhaven_wire::mcp::ChangeScope;
use davhaven_testkit::davhaven_wire::{EventView, GrantWrite, PrincipalWrite};
use chrono::{TimeZone, Utc};

use super::support::{Org, Person, PortCalls, World, principal_body};

/// A listing that asks for everything a `PROPFIND` of a home can ask for.
const EVERYTHING: HomeDetail = HomeDetail {
    dead_properties: true,
    invites: true,
    special: true,
};

/// The operations that read one thing at a time: a listing of many never calls them. (A listing finds the principal
/// of the home by name once, which is not a read per item and has its own assertion; the expansion of many principals
/// never reads one by name.)
const SINGLE_READS: &[&str] = &[
    "principals.get",
    "principals.addresses",
    "memberships.members",
    "memberships.groups_of",
    "bindings.find_for_calendar",
    "properties.list",
    "grants.for_calendar",
    "calendars.access_facts",
];

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

/// A calendar `slug` in the home of `owner`, with one dead property of its own.
async fn calendar_with_a_note(world: &World, org: &Org, owner: &Person, slug: &str) {
    let request = MkCalendar {
        path: world.collection(org, owner, slug),
        display_name: Some(format!("{slug} of {}", owner.name)),
        description: None,
        color: None,
        sort_order: None,
        components: None,
        timezone_ics: None,
        schedule_transp: None,
        dead_properties: vec![DeadProperty {
            name: PropertyName::new("urn:example", "note"),
            value_xml: format!("<note>{slug}</note>"),
        }],
    };
    world
        .services
        .calendars
        .mkcalendar(&world.dav(org, owner), request)
        .await
        .unwrap();
}

/// A viewer who owns two calendars that they share with two others each and sees `shared_in` calendars of as many
/// other owners.
async fn viewer(world: &World, org: &Org, name: &str, shared_in: usize, others: &[Person]) -> Person {
    let viewer = world.user(org, name).await;
    for slug in ["projects", "archive"] {
        calendar_with_a_note(world, org, &viewer, slug).await;
        for other in others.iter().take(2) {
            grant(world, org, &viewer, slug, other, GrantAccess::Read).await;
        }
    }
    for number in 0..shared_in {
        let owner = world.user(org, &format!("{name}-owner{number}")).await;
        calendar_with_a_note(world, org, &owner, "shared").await;
        grant(world, org, &owner, "shared", &viewer, GrantAccess::ReadWrite).await;
    }
    viewer
}

/// The port calls of one listing of the home of `viewer`, after the first listing that binds what the viewer sees
/// through grants (that one writes, once, and is not what is measured).
async fn cost_of_a_listing(world: &World, org: &Org, viewer: &Person, calls: &PortCalls) -> BTreeMap<String, u64> {
    let ctx = world.dav(org, viewer);
    let home = world.home(org, viewer);
    world
        .services
        .calendars
        .list_home_collections(&ctx, &home, EVERYTHING)
        .await
        .unwrap();
    calls.reset();
    world
        .services
        .calendars
        .list_home_collections(&ctx, &home, EVERYTHING)
        .await
        .unwrap();
    calls.all()
}

#[tokio::test]
async fn a_listing_of_a_home_costs_the_same_queries_for_two_calendars_as_for_many() {
    let calls = PortCalls::default();
    let _installed = metrics::set_default_local_recorder(&calls);
    let world = World::new();
    let acme = world.org("acme").await;
    let others = [world.user(&acme, "cora").await, world.user(&acme, "dina").await];
    let few = viewer(&world, &acme, "few", 2, &others).await;
    let many = viewer(&world, &acme, "many", 9, &others).await;

    let cost_few = cost_of_a_listing(&world, &acme, &few, &calls).await;
    for single in SINGLE_READS {
        assert_eq!(
            cost_few.get(*single).copied().unwrap_or(0),
            0,
            "a listing never reads one thing at a time ({single}): {cost_few:?}"
        );
    }
    assert!(
        cost_few.get("principals.get_by_name").copied().unwrap_or(0) <= 1,
        "the principal of the home is found once: {cost_few:?}"
    );
    // The owners of the calendars and the grantees of the invitations are two reads of principals, the rest one each.
    for (batch, most) in [
        ("principals.get_many", 2),
        ("bindings.find_for_calendars", 1),
        ("properties.list_many", 1),
        ("grants.for_calendars", 1),
        ("calendars.access_facts_many", 1),
    ] {
        assert!(
            cost_few.get(batch).copied().unwrap_or(0) <= most,
            "{batch} is {most} query at most: {cost_few:?}"
        );
    }
    assert_eq!(cost_few.get("properties.list_many").copied(), Some(1), "{cost_few:?}");

    let cost_many = cost_of_a_listing(&world, &acme, &many, &calls).await;
    assert_eq!(
        cost_many, cost_few,
        "nine calendars shared in cost exactly what two do: no query per calendar or per owner"
    );
}

#[tokio::test]
async fn a_listing_in_one_go_answers_what_the_collections_one_by_one_answer() {
    let world = World::new();
    let acme = world.org("acme").await;
    let others = [world.user(&acme, "cora").await, world.user(&acme, "dina").await];
    let anna = viewer(&world, &acme, "anna", 4, &others).await;
    let ctx = world.dav(&acme, &anna);
    let home = world.home(&acme, &anna);

    let listed = world
        .services
        .calendars
        .list_home_collections(&ctx, &home, EVERYTHING)
        .await
        .unwrap();
    // The calendars, in the order of the home, and then the inbox, the outbox and the notifications.
    assert_eq!(
        listed.len(),
        2 + 1 + 4 + 3,
        "personal, two own, four shared in, three special"
    );
    for collection in &listed {
        let single = world
            .services
            .calendars
            .get_collection(&ctx, &collection.path)
            .await
            .unwrap();
        assert_eq!(&single, collection, "{}", collection.path.format());
    }
    let own = listed
        .iter()
        .find(|collection| collection.path.format().ends_with("/projects/"))
        .unwrap();
    assert_eq!(own.dead_properties.len(), 1, "the dead property of the calendar");
    assert_eq!(
        own.invites.len(),
        2,
        "who the calendar is shared with, as the owner sees it"
    );
    let shared_in = listed
        .iter()
        .find(|collection| collection.display_name.starts_with("shared of "))
        .unwrap();
    assert!(
        shared_in.invites.is_empty(),
        "a sharee with read-write access sees no invitations"
    );

    // Without detail, the listing is the bindings of the home and nothing else.
    let plain = world
        .services
        .calendars
        .list_home_collections(&ctx, &home, HomeDetail::default())
        .await
        .unwrap();
    let bindings = world.services.calendars.list_home(&ctx, &anna.name).await.unwrap();
    assert_eq!(plain.len(), bindings.len());
    assert!(
        plain
            .iter()
            .all(|collection| collection.dead_properties.is_empty() && collection.invites.is_empty())
    );

    // Another principal's home is not visible.
    let error = world
        .services
        .calendars
        .list_home_collections(&world.dav(&acme, &others[0]), &home, EVERYTHING)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound);
}

fn principal_path(org: &Org, person: &Person) -> ResourcePath {
    ResourcePath::Principal {
        tenant: org.slug.clone(),
        principal: person.name.clone(),
    }
}

#[tokio::test]
async fn expanding_many_principals_costs_a_fixed_number_of_queries_and_answers_one_at_a_time() {
    let calls = PortCalls::default();
    let _installed = metrics::set_default_local_recorder(&calls);
    let world = World::new();
    let acme = world.org("acme").await;
    let globex = world.org("globex").await;
    let mut people = Vec::new();
    for name in ["anna", "ben", "cora", "dina", "emil", "fritz", "gina", "hugo"] {
        people.push(world.user(&acme, name).await);
    }
    let team = world.group(&acme, "team", &[&people[0], &people[1], &people[2]]).await;
    let ops = world.group(&acme, "ops", &[&people[2], &people[3]]).await;
    let robot = world.principal(&acme, "robot", PrincipalKind::Service).await;
    let gone = world.user(&acme, "gone").await;
    let admin = world.admin(&acme);
    let version = world.services.principals.get(&admin, &gone.name).await.unwrap().version;
    world
        .services
        .principals
        .delete(
            &admin,
            &gone.name,
            DeleteOptions {
                purge: false,
                notify_attendees: false,
                conditions: Conditions::if_match(version),
            },
        )
        .await
        .unwrap();
    let stranger = world.user(&globex, "stranger").await;

    let ctx = world.dav(&acme, &people[0]);
    let mut paths: Vec<ResourcePath> = people.iter().map(|person| principal_path(&acme, person)).collect();
    paths.extend([
        principal_path(&acme, &team),
        principal_path(&acme, &ops),
        principal_path(&acme, &robot),
        // Invisible ones: a deleted principal, a name that is nobody's, the same name twice, another tenant's principal
        // and a resource that is no principal.
        principal_path(&acme, &gone),
        ResourcePath::Principal {
            tenant: acme.slug.clone(),
            principal: davhaven_testkit::davhaven_domain::PrincipalName::parse("nobody").unwrap(),
        },
        principal_path(&acme, &people[2]),
        ResourcePath::Principal {
            tenant: TenantSlug::parse("globex").unwrap(),
            principal: stranger.name.clone(),
        },
        world.home(&acme, &people[0]),
    ]);

    calls.reset();
    let many = world
        .services
        .principals
        .dav_properties_many(&ctx, &paths)
        .await
        .unwrap();
    let cost = calls.all();
    for single in SINGLE_READS.iter().chain(&["principals.get_by_name"]) {
        assert_eq!(
            cost.get(*single).copied().unwrap_or(0),
            0,
            "expanding never reads one principal at a time ({single}): {cost:?}"
        );
    }
    for batch in [
        "principals.get_many_by_name",
        "principals.addresses_many",
        "memberships.members_of_many",
        "memberships.groups_of_many",
        "principals.get_many",
    ] {
        assert!(cost.get(batch).copied().unwrap_or(0) <= 1, "{batch}: {cost:?}");
    }
    assert_eq!(cost.get("principals.get_many_by_name").copied(), Some(1), "{cost:?}");

    // The answers are the ones of the reads of one path at a time, in the order of the request, repeats included.
    let mut one_by_one = Vec::new();
    for path in &paths {
        match world.services.principals.dav_properties(&ctx, path).await {
            Ok(props) => one_by_one.push(props),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => panic!("{path:?}: {error:?}"),
        }
    }
    assert_eq!(many, one_by_one);
    assert_eq!(
        many.len(),
        8 + 3 + 1,
        "eight users, two groups, the service principal and the repeated user"
    );
    let team_props = many.iter().find(|props| props.name == team.name).unwrap();
    assert_eq!(team_props.group_members.len(), 3, "the members of a group");
    let cora = many.iter().find(|props| props.name == people[2].name).unwrap();
    assert_eq!(cora.group_membership.len(), 2, "the groups of a member");
}

/// `count` attendees of every kind of address that names a principal of the tenant: a stored mail address, a `urn:uuid`,
/// a principal URL of this deployment and the login address of the tenant that no stored address matches (the stored one
/// is in another domain). Every attendee is another principal.
async fn attendees_of_every_kind(world: &World, org: &Org, prefix: &str, count: usize) -> Vec<EventAttendee> {
    let mut attendees = Vec::new();
    for number in 0..count {
        let stored = world.user(org, &format!("{prefix}-stored{number}")).await;
        let by_id = world.user(org, &format!("{prefix}-id{number}")).await;
        let by_url = world.user(org, &format!("{prefix}-url{number}")).await;
        let login = format!("{prefix}-login{number}");
        world
            .principal_write(
                org,
                &login,
                PrincipalWrite {
                    email: Some(Email::parse(&format!("{login}@elsewhere.example")).unwrap()),
                    ..principal_body(org, &login, PrincipalKind::User)
                },
            )
            .await
            .unwrap();
        for address in [
            format!("mailto:{}@{}.example", stored.name, org.slug),
            CalendarUserAddress::urn_uuid(by_id.id).as_str().to_owned(),
            format!("https://cal.example.org/dav/principals/{}/{}/", org.slug, by_url.name),
            format!("mailto:{login}@{}.example", org.slug),
        ] {
            attendees.push(EventAttendee {
                address: CalendarUserAddress::parse(&address).unwrap(),
                common_name: None,
                partstat: None,
                role: None,
                cutype: None,
                rsvp: None,
                schedule_agent: None,
            });
        }
    }
    attendees
}

#[tokio::test]
async fn the_attendees_of_a_write_cost_a_fixed_number_of_queries_whatever_their_number_or_kind() {
    let calls = PortCalls::default();
    let _installed = metrics::set_default_local_recorder(&calls);
    let world = World::new();
    let acme = world
        .org_with("acme", |settings| settings.login_address_is_cua = true)
        .await;
    let anna = world.user(&acme, "anna").await;
    world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    let few = attendees_of_every_kind(&world, &acme, "few", 2).await;
    let many = attendees_of_every_kind(&world, &acme, "many", 9).await;
    let ctx = world.api(
        &acme,
        &anna,
        &[Scope::CalendarsRead, Scope::EventsRead, Scope::EventsWrite],
    );
    let calendar = world.key(&anna, "work");
    let organizer = EventOrganizer {
        address: CalendarUserAddress::parse("mailto:anna@acme.example").unwrap(),
        common_name: None,
        sent_by: None,
    };
    let write = |uid: &str, attendees: Vec<EventAttendee>| EventWrite {
        target: None,
        event: EventView::from_data(EventData {
            uid: Some(Uid::parse(uid).unwrap()),
            summary: Some(uid.to_owned()),
            start: Some(EventTime::Utc(Utc.with_ymd_and_hms(2027, 3, 1, 9, 0, 0).unwrap())),
            end: Some(EventTime::Utc(Utc.with_ymd_and_hms(2027, 3, 1, 10, 0, 0).unwrap())),
            organizer: Some(organizer.clone()),
            attendees: Some(attendees),
            ..EventData::default()
        }),
        notify_attendees: false,
        if_match: None,
        scope: ChangeScope::All,
    };
    // The first write to a calendar makes the rest of what a write needs (it is not what is measured).
    world
        .services
        .objects
        .put_event(&ctx, &calendar, write("warm-up", Vec::new()))
        .await
        .unwrap();

    let mut costs = Vec::new();
    for (uid, attendees) in [("few", few), ("many", many)] {
        calls.reset();
        world
            .services
            .objects
            .put_event(&ctx, &calendar, write(uid, attendees))
            .await
            .unwrap();
        costs.push(calls.all());
    }
    let (cost_few, cost_many) = (&costs[0], &costs[1]);
    assert_eq!(
        cost_many, cost_few,
        "nine attendees of every kind cost exactly what two do: no query per attendee"
    );
    for (batch, most) in [
        ("principals.find_by_addresses", 1),
        ("principals.get_many", 1),
        ("principals.get_many_by_name", 1),
    ] {
        assert!(
            cost_many.get(batch).copied().unwrap_or(0) <= most,
            "{batch} is {most} query at most: {cost_many:?}"
        );
    }
    // The write reads the principal that acts and the home it writes into on their own (once each, whatever the attendees), and
    // none of the thirty-six attendees: the equality above is what says so.
    for single in ["principals.get", "principals.get_by_name"] {
        assert!(
            cost_many.get(single).copied().unwrap_or(0) <= 2,
            "{single} is the actor and the home, not an attendee: {cost_many:?}"
        );
    }
}
