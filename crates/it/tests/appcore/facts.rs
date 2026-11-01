//! Authorization facts are loaded in one store call per calendar a request is about (PLAN 2.6, F0.5): the use
//! cases never add a query to decide, and a home listing loads the facts of all its calendars at once.

use davhaven_testkit::davhaven_app::services::{
    CalendarDataSpec, CopyRequest, DeleteEventOptions, DeleteRequest, EventSearch, EventWrite, MkCalendar, MoveRequest,
    ObjectFilter, ObjectSelector, PageRequest, PropPatch, PropertyChange, PutRequest, ScheduleReply, ShareRequest,
    WritePrecondition,
};
use davhaven_testkit::davhaven_domain::{CalendarKind, ExternalKey, ResourcePath, Scope};
use davhaven_testkit::davhaven_wire::{BatchItem, BatchRequest, EventView};

use super::support::{Fixture, World, fixture, ics};

fn put(path: &ResourcePath, body: &str) -> PutRequest {
    PutRequest {
        path: path.clone(),
        body: body.to_owned(),
        content_type: None,
        preconditions: WritePrecondition::none(),
        schedule_reply: ScheduleReply::Send,
    }
}

/// How often facts were loaded by `operation`.
async fn loads<T>(world: &World, operation: impl std::future::Future<Output = T>) -> (u32, T) {
    world.reset_fact_loads();
    let result = operation.await;
    (world.fact_loads(), result)
}

fn write(key: &str) -> EventWrite {
    EventWrite {
        target: Some(ObjectSelector::Key(ExternalKey::parse(key).unwrap())),
        event: EventView::from_data(davhaven_testkit::davhaven_domain::EventData {
            summary: Some("Event".to_owned()),
            start: Some(
                serde_json::from_value(serde_json::json!({"date_time": "2027-03-01T09:00:00", "time_zone": "UTC"}))
                    .unwrap(),
            ),
            end: Some(
                serde_json::from_value(serde_json::json!({"date_time": "2027-03-01T10:00:00", "time_zone": "UTC"}))
                    .unwrap(),
            ),
            ..davhaven_testkit::davhaven_domain::EventData::default()
        }),
        notify_attendees: false,
        if_match: None,
        scope: davhaven_testkit::davhaven_wire::mcp::ChangeScope::All,
    }
}

#[tokio::test]
async fn every_dav_operation_loads_the_facts_of_a_collection_once() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    let dav = world.dav(&acme, &anna);
    let objects = &world.services.objects;
    let calendars = &world.services.calendars;
    let personal = world.collection(&acme, &anna, "personal");
    let path = world.object(&acme, &anna, "personal", "a.ics");
    let other = world.object(&acme, &anna, "work", "a.ics");

    assert_eq!(
        loads(&world, objects.put(&dav, put(&path, &ics("a", "A")))).await.0,
        1,
        "PUT, create"
    );
    assert_eq!(
        loads(&world, objects.put(&dav, put(&path, &ics("a", "A2")))).await.0,
        1,
        "PUT, replace"
    );
    assert_eq!(loads(&world, objects.get(&dav, &path)).await.0, 1, "GET");
    assert_eq!(
        loads(
            &world,
            objects.multiget(&dav, &personal, vec![path.clone()], CalendarDataSpec::default())
        )
        .await
        .0,
        1,
        "calendar-multiget"
    );
    assert_eq!(
        loads(
            &world,
            objects.query(&dav, &personal, ObjectFilter::default(), CalendarDataSpec::default())
        )
        .await
        .0,
        1,
        "calendar-query"
    );
    assert_eq!(
        loads(&world, objects.sync(&dav, &personal, None, None)).await.0,
        1,
        "sync-collection"
    );
    assert_eq!(
        loads(&world, calendars.get_collection(&dav, &personal)).await.0,
        1,
        "PROPFIND of a collection"
    );
    assert_eq!(
        loads(
            &world,
            calendars.proppatch(
                &dav,
                &personal,
                PropPatch {
                    changes: vec![PropertyChange::DisplayName(Some("Mine".to_owned()))]
                }
            )
        )
        .await
        .0,
        1,
        "PROPPATCH"
    );
    assert_eq!(
        loads(
            &world,
            objects.copy_to(
                &dav,
                CopyRequest {
                    from: path.clone(),
                    to: other.clone(),
                    overwrite: false
                }
            )
        )
        .await
        .0,
        2,
        "COPY reads the source collection and writes the target collection"
    );
    assert_eq!(
        loads(
            &world,
            objects.move_to(
                &dav,
                MoveRequest {
                    from: other.clone(),
                    to: world.object(&acme, &anna, "work", "b.ics"),
                    overwrite: false,
                    preconditions: WritePrecondition::none()
                }
            )
        )
        .await
        .0,
        2,
        "MOVE locates both sides"
    );
    assert_eq!(
        loads(
            &world,
            objects.delete(
                &dav,
                DeleteRequest {
                    path: path.clone(),
                    preconditions: WritePrecondition::none(),
                    schedule_reply: ScheduleReply::Send
                }
            )
        )
        .await
        .0,
        1,
        "DELETE"
    );
    let mk = MkCalendar {
        path: world.collection(&acme, &anna, "projects"),
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
        loads(&world, calendars.mkcalendar(&dav, mk)).await.0,
        1,
        "MKCALENDAR loads the facts of what it made"
    );
    assert_eq!(
        loads(
            &world,
            world.services.sharing.share(&dav, &personal, ShareRequest::default())
        )
        .await
        .0,
        1,
        "CS:share"
    );
}

#[tokio::test]
async fn a_home_listing_loads_the_facts_of_all_its_calendars_in_one_call() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    let team = world.group(&acme, "team", &[&anna]).await;
    for index in 0..6 {
        world
            .calendar(&acme, &anna, &format!("cal-{index}"), CalendarKind::User)
            .await;
    }
    world.calendar(&acme, &team, "shared", CalendarKind::Group).await;
    let dav = world.dav(&acme, &anna);

    // The first listing also creates the lazy binding; the facts are still loaded once for the whole listing.
    let (first, home) = loads(&world, world.services.calendars.list_home(&dav, &anna.name)).await;
    assert_eq!(home.unwrap().len(), 8);
    assert_eq!(first, 1);
    let (second, home) = loads(&world, world.services.calendars.list_home(&dav, &anna.name)).await;
    assert_eq!(home.unwrap().len(), 8);
    assert_eq!(second, 1, "not one query per calendar");
}

#[tokio::test]
async fn the_json_interface_loads_the_facts_of_a_calendar_once_per_deciding_transaction() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    world.calendar(&acme, &anna, "work", CalendarKind::User).await;
    let api = world.api(
        &acme,
        &anna,
        &[
            Scope::CalendarsRead,
            Scope::CalendarsWrite,
            Scope::EventsRead,
            Scope::EventsWrite,
        ],
    );
    let calendar = world.key(&anna, "work");
    let objects = &world.services.objects;
    let selector = ObjectSelector::Key(ExternalKey::parse("k-1").unwrap());

    // A write decides before it reads (the merge and the validation run outside any transaction, so that the
    // calendar is locked for the store only) and again under the lock: two transactions, one load each.
    assert_eq!(
        loads(&world, objects.put_event(&api, &calendar, write("k-1"))).await.0,
        2,
        "create"
    );
    assert_eq!(
        loads(&world, objects.put_event(&api, &calendar, write("k-1"))).await.0,
        1,
        "a no-op write"
    );
    assert_eq!(
        loads(&world, objects.get_event(&api, &calendar, &selector, None))
            .await
            .0,
        1,
        "read"
    );
    assert_eq!(
        loads(
            &world,
            objects.list(&api, &calendar, ObjectFilter::default(), PageRequest::first())
        )
        .await
        .0,
        1,
        "list"
    );
    assert_eq!(
        loads(&world, objects.changes(&api, &calendar, None, None)).await.0,
        1,
        "changes"
    );
    assert_eq!(
        loads(
            &world,
            world
                .services
                .sharing
                .list_grants(&api, &calendar, PageRequest::first())
        )
        .await
        .0,
        1,
        "list grants"
    );
    assert_eq!(
        loads(
            &world,
            objects.delete_event(&api, &calendar, &selector, DeleteEventOptions::default())
        )
        .await
        .0,
        1,
        "delete"
    );
    assert_eq!(
        loads(&world, world.services.calendars.get(&api, &calendar)).await.0,
        1,
        "read the calendar"
    );
}

#[tokio::test]
async fn a_batch_loads_the_facts_twice_whatever_its_size() {
    let Fixture { world, acme, .. } = fixture().await;
    let svc = world
        .principal(
            &acme,
            "svc",
            davhaven_testkit::davhaven_domain::PrincipalKind::Service,
        )
        .await;
    world.calendar(&acme, &svc, "holidays", CalendarKind::Managed).await;
    let items: Vec<BatchItem> = (0..25)
        .map(|index| BatchItem {
            external_key: ExternalKey::parse(&format!("k-{index}")).unwrap(),
            event: None,
            ical: Some(ics(&format!("uid-{index}"), "Holiday")),
        })
        .collect();
    let (loaded, result) = loads(
        &world,
        world.services.objects.batch(
            &world.admin(&acme),
            &world.key(&svc, "holidays"),
            BatchRequest {
                items,
                ..BatchRequest::default()
            },
        ),
    )
    .await;
    assert_eq!(result.unwrap().results.len(), 25);
    // Before the read and under the lock, never once per item.
    assert_eq!(loaded, 2);
}

#[tokio::test]
async fn a_search_across_calendars_loads_the_facts_of_all_of_them_at_once() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    for index in 0..5 {
        world
            .calendar(&acme, &anna, &format!("cal-{index}"), CalendarKind::User)
            .await;
    }
    let mcp = world.mcp(&acme, &anna, &[Scope::McpRead]);
    let (loaded, result) = loads(
        &world,
        world
            .services
            .objects
            .search_events(&mcp, EventSearch::default(), PageRequest::first()),
    )
    .await;
    result.unwrap();
    assert_eq!(loaded, 1, "six calendars, one load");
}

#[tokio::test]
async fn the_api_listing_of_calendars_loads_the_facts_of_all_of_them_at_once() {
    let Fixture { world, acme, anna, .. } = fixture().await;
    for index in 0..7 {
        world
            .calendar(&acme, &anna, &format!("cal-{index}"), CalendarKind::User)
            .await;
    }
    let api = world.api(&acme, &anna, &[Scope::CalendarsRead]);
    let (loaded, listed) = loads(
        &world,
        world
            .services
            .calendars
            .list_owned(&api, &anna.name, PageRequest::first()),
    )
    .await;
    assert_eq!(listed.unwrap().items.len(), 8, "the personal calendar and seven more");
    assert_eq!(loaded, 1, "not one load per calendar");
}
