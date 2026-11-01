//! Batch upserts into managed calendars: one transaction, all or nothing, UIDs from keys, no-ops, sequence bumps,
//! replace scopes, delete guards and the rule that a batch never schedules.

use davhaven_testkit::davhaven_app::services::{CalendarRef, ObjectService};
use davhaven_testkit::davhaven_domain::{
    CalendarId, CalendarKind, ErrorKind, EventData, EventTime, EventType, ExternalKey, PrincipalKind, Scope, Uid,
};
use davhaven_testkit::davhaven_wire::{
    BatchItem, BatchMode, BatchOutcome, BatchRequest, BatchResult, EventView, ProblemCode,
};
use chrono::{TimeZone, Utc};

use super::scheduler::{Recording, service_with};
use super::support::{Fixture, Org, Person, World, fixture, ics};

fn key(text: &str) -> ExternalKey {
    ExternalKey::parse(text).unwrap()
}

fn event_item(external_key: &str, summary: &str, day: u32) -> BatchItem {
    let at = |hour| EventTime::Utc(Utc.with_ymd_and_hms(2027, 5, day, hour, 0, 0).unwrap());
    BatchItem {
        external_key: key(external_key),
        event: Some(EventView::from_data(EventData {
            summary: Some(summary.to_owned()),
            start: Some(at(9)),
            end: Some(at(10)),
            ..EventData::default()
        })),
        ical: None,
    }
}

fn ical_item(external_key: &str, text: &str) -> BatchItem {
    BatchItem {
        external_key: key(external_key),
        event: None,
        ical: Some(text.to_owned()),
    }
}

fn merge(items: Vec<BatchItem>) -> BatchRequest {
    BatchRequest {
        items,
        ..BatchRequest::default()
    }
}

fn replace(prefix: &str, items: Vec<BatchItem>) -> BatchRequest {
    BatchRequest {
        mode: BatchMode::Replace,
        replace_scope_prefix: Some(prefix.to_owned()),
        items,
        ..BatchRequest::default()
    }
}

fn outcomes(result: &BatchResult) -> Vec<(String, BatchOutcome)> {
    result
        .results
        .iter()
        .map(|entry| (entry.external_key.as_str().to_owned(), entry.outcome))
        .collect()
}

struct Managed {
    f: Fixture,
    svc: Person,
    calendar: CalendarRef,
    id: CalendarId,
}

impl Managed {
    fn world(&self) -> &World {
        &self.f.world
    }

    fn acme(&self) -> &Org {
        &self.f.acme
    }

    async fn seq(&self) -> u64 {
        self.world()
            .services
            .calendars
            .get(&self.world().admin(self.acme()), &self.calendar)
            .await
            .unwrap()
            .sync_token
            .seq
    }

    async fn batch(
        &self,
        request: BatchRequest,
    ) -> Result<BatchResult, davhaven_testkit::davhaven_app::error::AppError> {
        self.world()
            .services
            .objects
            .batch(&self.world().admin(self.acme()), &self.calendar, request)
            .await
    }

    async fn stored(&self, external_key: &str) -> Option<davhaven_testkit::davhaven_domain::StoredObject> {
        self.world()
            .read(self.acme())
            .await
            .objects()
            .get_by_external_key(self.id, &key(external_key))
            .await
            .ok()
    }

    async fn events(&self) -> usize {
        self.world()
            .events_of(self.acme(), EventType::CalendarObjectsChanged)
            .await
            .len()
    }
}

async fn managed() -> Managed {
    let f = fixture().await;
    let svc = f.world.principal(&f.acme, "svc", PrincipalKind::Service).await;
    let view = f.world.calendar(&f.acme, &svc, "holidays", CalendarKind::Managed).await;
    let calendar = f.world.key(&svc, "holidays");
    Managed {
        f,
        svc,
        calendar,
        id: view.id,
    }
}

#[tokio::test]
async fn a_batch_writes_every_item_in_one_transaction_and_tells_the_world_once() {
    let m = managed().await;
    let start = m.seq().await;
    let request = merge(vec![
        event_item("h:1", "New Year", 1),
        event_item("h:2", "Labour Day", 2),
        ical_item("h:3", &ics("custom-uid", "From iCalendar")),
    ]);
    let result = m.batch(request.clone()).await.unwrap();
    assert!(!result.has_failures());
    assert_eq!(
        outcomes(&result),
        vec![
            ("h:1".to_owned(), BatchOutcome::Created),
            ("h:2".to_owned(), BatchOutcome::Created),
            ("h:3".to_owned(), BatchOutcome::Created),
        ]
    );
    assert_eq!(
        result.results[0].uid,
        Some(Uid::deterministic(m.id, &key("h:1"))),
        "UUIDv5(calendar, key)"
    );
    assert_eq!(
        result.results[2].uid,
        Some(Uid::parse("custom-uid").unwrap()),
        "iCalendar items keep their UID"
    );
    assert!(
        result
            .results
            .iter()
            .all(|entry| entry.etag.is_some() && entry.uri.is_some() && entry.problem.is_none())
    );
    assert_eq!(m.seq().await, start + 3, "the log advances once per written object");
    assert_eq!(result.sync_token.seq, start + 3);

    // One event describes the whole batch, with the token the batch left behind.
    let events = m.world().events_of(m.acme(), EventType::CalendarObjectsChanged).await;
    assert_eq!(events.len(), 1);
    let payload = World::objects_changed(&events[0]);
    assert_eq!(payload.changes.len(), 3);
    assert_eq!(payload.sync_token, result.sync_token);
    let keys: Vec<Option<ExternalKey>> = payload
        .changes
        .iter()
        .map(|change| change.external_key.clone())
        .collect();
    assert_eq!(keys, vec![Some(key("h:1")), Some(key("h:2")), Some(key("h:3"))]);

    // The same batch again changes nothing: the same ETags, the same token, no event.
    let again = m.batch(request).await.unwrap();
    assert_eq!(
        outcomes(&again).iter().map(|(_, outcome)| *outcome).collect::<Vec<_>>(),
        vec![BatchOutcome::Unchanged; 3]
    );
    assert_eq!(
        again.results.iter().map(|entry| entry.etag.clone()).collect::<Vec<_>>(),
        result
            .results
            .iter()
            .map(|entry| entry.etag.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(again.sync_token, result.sync_token);
    assert_eq!(m.events().await, 1);
}

/// A batch as a client writes it: JSON, with `null` for the fields it has no value for.
fn json_batch(location: &serde_json::Value) -> BatchRequest {
    serde_json::from_value(serde_json::json!({
        "items": [{
            "external_key": "course:1",
            "event": {
                "summary": "Course",
                "start": {"date_time": "2027-05-04T09:00:00Z"},
                "end": {"date_time": "2027-05-04T10:00:00Z"},
                "location": location,
                "description": null,
                "url": null,
            }
        }]
    }))
    .unwrap()
}

#[tokio::test]
async fn a_batch_item_with_null_removes_the_field_an_earlier_batch_set_and_then_stays_quiet() {
    let m = managed().await;
    let first = m.batch(json_batch(&serde_json::json!("Room 1"))).await.unwrap();
    assert_eq!(first.results[0].outcome, BatchOutcome::Created);
    let created = m.stored("course:1").await.unwrap();
    assert!(created.data.contains("LOCATION:Room 1"), "{}", created.data);
    assert!(
        !created.data.contains("DESCRIPTION") && !created.data.contains("URL"),
        "null on create writes nothing: {}",
        created.data
    );

    // The daily reconcile sends the location as null: the drift is repaired, the sequence of the object goes up.
    let after_first = (m.seq().await, m.events().await);
    let repaired = m.batch(json_batch(&serde_json::Value::Null)).await.unwrap();
    assert_eq!(repaired.results[0].outcome, BatchOutcome::Updated);
    let stored = m.stored("course:1").await.unwrap();
    assert!(!stored.data.contains("LOCATION"), "{}", stored.data);
    assert!(stored.data.contains("SUMMARY:Course"), "{}", stored.data);
    assert!(stored.sequence > created.sequence);
    assert_ne!(stored.etag, created.etag);
    assert_eq!(
        (m.seq().await, m.events().await),
        (after_first.0 + 1, after_first.1 + 1)
    );

    // The same batch the next day changes nothing: same ETag, same token, no event.
    let quiet = (m.seq().await, m.events().await);
    let again = m.batch(json_batch(&serde_json::Value::Null)).await.unwrap();
    assert_eq!(again.results[0].outcome, BatchOutcome::Unchanged);
    assert_eq!(again.results[0].etag.as_ref(), Some(&stored.etag));
    assert_eq!((m.seq().await, m.events().await), quiet);

    // Leaving the member out is not the same as null: it keeps what is stored.
    m.batch(json_batch(&serde_json::json!("Room 2"))).await.unwrap();
    let without_location: BatchRequest = serde_json::from_value(serde_json::json!({
        "items": [{"external_key": "course:1", "event": {"summary": "Course"}}]
    }))
    .unwrap();
    let kept = m.batch(without_location).await.unwrap();
    assert_eq!(kept.results[0].outcome, BatchOutcome::Unchanged);
    assert!(m.stored("course:1").await.unwrap().data.contains("LOCATION:Room 2"));
}

#[tokio::test]
async fn a_changed_object_gets_a_higher_sequence_and_unchanged_objects_stay_as_they_are() {
    let m = managed().await;
    m.batch(merge(vec![
        event_item("h:1", "New Year", 1),
        event_item("h:2", "Labour Day", 2),
    ]))
    .await
    .unwrap();
    let first = m.stored("h:1").await.unwrap();
    let second = m.stored("h:2").await.unwrap();

    let result = m
        .batch(merge(vec![
            event_item("h:1", "New Year's Day", 1),
            event_item("h:2", "Labour Day", 2),
        ]))
        .await
        .unwrap();
    assert_eq!(
        outcomes(&result),
        vec![
            ("h:1".to_owned(), BatchOutcome::Updated),
            ("h:2".to_owned(), BatchOutcome::Unchanged)
        ]
    );
    let changed = m.stored("h:1").await.unwrap();
    assert!(
        changed.sequence > first.sequence,
        "{} then {}",
        first.sequence,
        changed.sequence
    );
    assert_ne!(changed.etag, first.etag);
    assert_eq!(changed.id, first.id, "the same object");
    assert_eq!(m.stored("h:2").await.unwrap().etag, second.etag, "untouched");
    let events = m.world().events_of(m.acme(), EventType::CalendarObjectsChanged).await;
    let last = World::objects_changed(events.last().unwrap());
    assert_eq!(last.changes.len(), 1, "only what changed is listed");

    // The UID of an object never changes behind the key.
    let hijack = m
        .batch(merge(vec![ical_item("h:2", &ics("another-uid", "Other"))]))
        .await
        .unwrap();
    assert!(hijack.has_failures());
}

#[tokio::test]
async fn explicit_deletes_remove_objects_and_unknown_keys_are_unchanged() {
    let m = managed().await;
    m.batch(merge(vec![
        event_item("h:1", "New Year", 1),
        event_item("h:2", "Labour Day", 2),
    ]))
    .await
    .unwrap();
    let start = m.seq().await;
    let request = BatchRequest {
        items: vec![event_item("h:3", "Christmas", 25)],
        deletes: vec![key("h:1"), key("h:unknown")],
        ..BatchRequest::default()
    };
    let result = m.batch(request).await.unwrap();
    assert_eq!(
        outcomes(&result),
        vec![
            ("h:3".to_owned(), BatchOutcome::Created),
            ("h:1".to_owned(), BatchOutcome::Deleted),
            ("h:unknown".to_owned(), BatchOutcome::Unchanged),
        ]
    );
    assert!(m.stored("h:1").await.is_none());
    assert!(m.stored("h:2").await.is_some());
    assert_eq!(m.seq().await, start + 2);
    let events = m.world().events_of(m.acme(), EventType::CalendarObjectsChanged).await;
    let last = World::objects_changed(events.last().unwrap());
    assert_eq!(
        last.changes.len(),
        2,
        "the creation and the deletion, nothing for the unknown key"
    );
}

#[tokio::test]
async fn a_batch_is_all_or_nothing_and_says_what_went_wrong_with_which_entry() {
    let m = managed().await;
    m.batch(merge(vec![event_item("keep", "Existing", 1)])).await.unwrap();
    let start = m.seq().await;
    let events = m.events().await;

    let request = merge(vec![
        event_item("ok:1", "Fine", 3),
        ical_item("bad", "this is not iCalendar"),
        event_item("keep", "Existing changed", 1),
    ]);
    let result = m.batch(request).await.unwrap();
    assert!(result.has_failures());
    let failed = &result.results[1];
    assert_eq!(failed.outcome, BatchOutcome::Failed);
    let problem = failed.problem.as_ref().expect("the failed entry carries its problem");
    assert_eq!(
        problem.code,
        ProblemCode::from_error(
            ErrorKind::Invalid,
            Some(&davhaven_testkit::davhaven_domain::Precondition::ValidCalendarData(
                String::new()
            ))
        )
    );
    // The others report what they would have done, without ETags of writes that never happened.
    assert_eq!(result.results[0].outcome, BatchOutcome::Created);
    assert_eq!(result.results[2].outcome, BatchOutcome::Updated);
    assert!(result.results[0].etag.is_none() && result.results[2].etag.is_none());

    // Nothing was written: no object, no log entry, no event, the old content.
    assert!(m.stored("ok:1").await.is_none());
    assert_eq!(m.seq().await, start);
    assert_eq!(result.sync_token.seq, start, "the token is the unchanged one");
    assert_eq!(m.events().await, events);
    assert!(m.stored("keep").await.unwrap().data.contains("Existing"));
    assert!(!m.stored("keep").await.unwrap().data.contains("changed"));
}

#[tokio::test]
async fn the_calendar_decides_which_components_a_batch_may_store() {
    let m = managed().await;
    let body = davhaven_testkit::davhaven_wire::CalendarWrite {
        kind: None,
        display_name: "Holidays".to_owned(),
        description: None,
        color: None,
        sort_order: None,
        components: Some(vec![davhaven_testkit::davhaven_domain::ComponentKind::Event]),
    };
    m.world()
        .services
        .calendars
        .upsert(
            &m.world().admin(m.acme()),
            davhaven_testkit::davhaven_app::services::CalendarSpec {
                owner: m.svc.name.clone(),
                slug: davhaven_testkit::davhaven_domain::CalendarSlug::parse("holidays").unwrap(),
                body,
            },
            davhaven_testkit::davhaven_app::services::Conditions::none(),
        )
        .await
        .unwrap();
    let todo = davhaven_testkit::davhaven_fixtures::event::EventBuilder::todo("t-1")
        .summary("Task")
        .build();
    let result = m.batch(merge(vec![ical_item("task", &todo)])).await.unwrap();
    assert!(result.has_failures());
    assert_eq!(
        result.results[0].problem.as_ref().map(|problem| problem.code),
        Some(ProblemCode::from_error(
            ErrorKind::Invalid,
            Some(&davhaven_testkit::davhaven_domain::Precondition::SupportedCalendarComponent)
        ))
    );
}

#[tokio::test]
async fn replace_deletes_what_is_missing_inside_its_scope_and_nothing_outside() {
    let m = managed().await;
    m.batch(merge(vec![
        event_item("feed-a:1", "A1", 1),
        event_item("feed-a:2", "A2", 2),
        event_item("feed-a:3", "A3", 3),
        event_item("feed-b:1", "B1", 4),
    ]))
    .await
    .unwrap();

    let result = m
        .batch(replace(
            "feed-a:",
            vec![event_item("feed-a:1", "A1", 1), event_item("feed-a:4", "A4", 5)],
        ))
        .await
        .unwrap();
    let mut seen = outcomes(&result);
    seen.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        seen,
        vec![
            ("feed-a:1".to_owned(), BatchOutcome::Unchanged),
            ("feed-a:2".to_owned(), BatchOutcome::Deleted),
            ("feed-a:3".to_owned(), BatchOutcome::Deleted),
            ("feed-a:4".to_owned(), BatchOutcome::Created),
        ]
    );
    assert!(m.stored("feed-a:2").await.is_none() && m.stored("feed-a:3").await.is_none());
    assert!(
        m.stored("feed-b:1").await.is_some(),
        "another integration's objects are out of scope"
    );
    assert!(m.stored("feed-a:4").await.is_some());

    // max_deletes bounds the damage: the request is refused as a whole.
    let start = m.seq().await;
    let guarded = BatchRequest {
        max_deletes: Some(0),
        ..replace("feed-a:", vec![])
    };
    let error = m
        .batch(BatchRequest {
            allow_empty: true,
            ..guarded
        })
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Invalid);
    assert_eq!(
        error.field_errors().first().map(|field| field.pointer),
        Some("/max_deletes")
    );
    assert_eq!(m.seq().await, start, "nothing was deleted");

    // An empty replace deletes the scope when the caller says so on purpose.
    let wiped = m
        .batch(BatchRequest {
            allow_empty: true,
            ..replace("feed-a:", vec![])
        })
        .await
        .unwrap();
    assert!(wiped.results.iter().all(|entry| entry.outcome == BatchOutcome::Deleted));
    assert!(m.stored("feed-a:1").await.is_none() && m.stored("feed-b:1").await.is_some());
}

#[tokio::test]
async fn requests_that_break_their_own_rules_are_refused_before_anything_happens() {
    let m = managed().await;
    let start = m.seq().await;
    let both = BatchItem {
        external_key: key("x"),
        event: event_item("x", "X", 1).event,
        ical: Some(ics("x", "X")),
    };
    let neither = BatchItem {
        external_key: key("y"),
        event: None,
        ical: None,
    };
    let cases: Vec<(&str, BatchRequest)> = vec![
        ("both event and ical", merge(vec![both])),
        ("neither event nor ical", merge(vec![neither])),
        (
            "duplicate keys",
            merge(vec![event_item("d", "D", 1), event_item("d", "D2", 2)]),
        ),
        (
            "a key to write and delete",
            BatchRequest {
                items: vec![event_item("d", "D", 1)],
                deletes: vec![key("d")],
                ..BatchRequest::default()
            },
        ),
        ("an empty batch", BatchRequest::default()),
        (
            "replace without a scope",
            BatchRequest {
                mode: BatchMode::Replace,
                items: vec![event_item("d", "D", 1)],
                ..BatchRequest::default()
            },
        ),
        (
            "a scope in merge mode",
            BatchRequest {
                replace_scope_prefix: Some("feed:".to_owned()),
                items: vec![event_item("d", "D", 1)],
                ..BatchRequest::default()
            },
        ),
    ];
    for (name, request) in cases {
        let error = m.batch(request).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid, "{name}");
    }
    assert_eq!(m.seq().await, start);

    // The number of entries is limited by the API limits.
    let small = World::with(|deps| deps.limits.api.max_batch_items = 3);
    let org = small.org("acme").await;
    let owner = small.principal(&org, "svc", PrincipalKind::Service).await;
    small.calendar(&org, &owner, "holidays", CalendarKind::Managed).await;
    let items: Vec<BatchItem> = (0..4)
        .map(|index| event_item(&format!("k{index}"), "K", 1 + index))
        .collect();
    let error = small
        .services
        .objects
        .batch(&small.admin(&org), &small.key(&owner, "holidays"), merge(items))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Invalid);
}

#[tokio::test]
async fn a_batch_never_schedules_and_needs_events_write_on_a_calendar_the_caller_may_write() {
    let m = managed().await;
    let Fixture { world, acme, anna, .. } = &m.f;

    // Objects with attendees are stored as they are: nobody is told.
    let scheduler = Recording::default();
    let objects = service_with(world, &scheduler);
    let invitation = davhaven_testkit::davhaven_fixtures::event::EventBuilder::event("meeting-1")
        .summary("Meeting")
        .starts(davhaven_testkit::davhaven_fixtures::event::When::utc(
            2027, 5, 1, 9, 0,
        ))
        .organizer(davhaven_testkit::davhaven_fixtures::event::Organizer::new(
            "mailto:svc@acme.example",
        ))
        .attendee(davhaven_testkit::davhaven_fixtures::event::Attendee::new(
            "mailto:anna@acme.example",
        ))
        .build();
    let result = objects
        .batch(
            &world.admin(acme),
            &m.calendar,
            merge(vec![ical_item("meeting", &invitation)]),
        )
        .await
        .unwrap();
    assert_eq!(result.results[0].outcome, BatchOutcome::Created);
    assert!(scheduler.calls().is_empty(), "{:?}", scheduler.calls());

    // DAV has no batch; the API needs events:write; tenant tokens do not reach personal calendars.
    let dav = world.dav(acme, anna);
    assert_eq!(
        world
            .services
            .objects
            .batch(&dav, &m.calendar, merge(vec![event_item("k", "K", 1)]))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    let reader = world.tenant_token(
        acme,
        davhaven_testkit::davhaven_domain::ScopeSet::of(&[Scope::EventsRead, Scope::CalendarsRead]),
    );
    assert_eq!(
        world
            .services
            .objects
            .batch(&reader, &m.calendar, merge(vec![event_item("k", "K", 1)]))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );
    assert_eq!(
        world
            .services
            .objects
            .batch(
                &world.admin(acme),
                &world.key(anna, "personal"),
                merge(vec![event_item("k", "K", 1)])
            )
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );

    // A principal token that owns the managed calendar may write; a read-only sharee may not.
    let owner = world.api(
        acme,
        &m.svc,
        &[Scope::CalendarsRead, Scope::EventsRead, Scope::EventsWrite],
    );
    assert!(
        world
            .services
            .objects
            .batch(&owner, &m.calendar, merge(vec![event_item("k", "K", 1)]))
            .await
            .is_ok()
    );
    world
        .services
        .sharing
        .put_grant(
            &world.admin(acme),
            davhaven_testkit::davhaven_app::services::GrantSpec {
                calendar: m.calendar.clone(),
                grantee: anna.name.clone(),
                body: davhaven_testkit::davhaven_wire::GrantWrite {
                    access: davhaven_testkit::davhaven_domain::GrantAccess::Read,
                    required: false,
                },
            },
            davhaven_testkit::davhaven_app::services::Conditions::none(),
        )
        .await
        .unwrap();
    let sharee = world.api(
        acme,
        anna,
        &[Scope::CalendarsRead, Scope::EventsRead, Scope::EventsWrite],
    );
    assert_eq!(
        world
            .services
            .objects
            .batch(&sharee, &m.calendar, merge(vec![event_item("k2", "K2", 2)]))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Forbidden
    );
}

#[tokio::test]
async fn a_replace_batch_without_items_needs_allow_empty_even_when_it_lists_deletes() {
    let m = managed().await;
    m.batch(merge(vec![
        event_item("feed-a:1", "A1", 1),
        event_item("feed-a:2", "A2", 2),
    ]))
    .await
    .unwrap();
    let start = m.seq().await;
    let events = m.events().await;

    // `deletes` lists one key, but a replace without items deletes the whole scope: the guard must not be satisfied by
    // the list.
    let request = BatchRequest {
        mode: BatchMode::Replace,
        replace_scope_prefix: Some("feed-a:".to_owned()),
        deletes: vec![key("feed-a:1")],
        ..BatchRequest::default()
    };
    let error = m.batch(request.clone()).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Invalid);
    assert_eq!(
        error.field_errors().first().map(|field| field.pointer),
        Some("/allow_empty")
    );
    assert!(m.stored("feed-a:1").await.is_some() && m.stored("feed-a:2").await.is_some());
    assert_eq!(m.seq().await, start, "nothing was deleted");
    assert_eq!(m.events().await, events);

    // Said on purpose, the same request empties the scope.
    let wiped = m
        .batch(BatchRequest {
            allow_empty: true,
            ..request
        })
        .await
        .unwrap();
    assert_eq!(wiped.results.len(), 2);
    assert!(wiped.results.iter().all(|entry| entry.outcome == BatchOutcome::Deleted));
    assert!(m.stored("feed-a:1").await.is_none() && m.stored("feed-a:2").await.is_none());
}

#[tokio::test]
async fn after_the_first_failure_in_the_store_the_rest_of_a_batch_is_validated_but_not_stored() {
    let m = managed().await;
    let start = m.seq().await;
    let events = m.events().await;
    // The second item takes the UID of the first, which the store refuses; the third is fine and must not be stored.
    let result = m
        .batch(merge(vec![
            ical_item("k:1", &ics("same-uid", "One")),
            ical_item("k:2", &ics("same-uid", "Two")),
            ical_item("k:3", &ics("other-uid", "Three")),
        ]))
        .await
        .unwrap();
    assert!(result.has_failures());
    assert_eq!(
        outcomes(&result),
        vec![
            ("k:1".to_owned(), BatchOutcome::Created),
            ("k:2".to_owned(), BatchOutcome::Failed),
            ("k:3".to_owned(), BatchOutcome::Created),
        ],
        "the entries say what they would have done"
    );
    assert!(
        result.results.iter().all(|entry| entry.etag.is_none()),
        "no ETag of a write that never happened"
    );
    assert!(m.stored("k:1").await.is_none() && m.stored("k:3").await.is_none());
    assert_eq!(m.seq().await, start);
    assert_eq!(result.sync_token.seq, start, "the token is the unchanged one");
    assert_eq!(m.events().await, events);
}

#[tokio::test]
async fn concurrent_batches_for_one_key_both_succeed_and_the_later_builds_on_the_earlier() {
    let m = managed().await;
    let start = m.seq().await;
    let (a, b) = tokio::join!(
        m.batch(merge(vec![event_item("h:1", "From A", 1)])),
        m.batch(merge(vec![event_item("h:1", "From B", 1)])),
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert!(!a.has_failures() && !b.has_failures());
    let stored = m.stored("h:1").await.unwrap();
    assert!(
        stored.data.contains("From A") || stored.data.contains("From B"),
        "{}",
        stored.data
    );
    assert_eq!(m.seq().await, start + 2, "one creation and one update, nothing lost");
    assert!(
        stored.sequence >= 1,
        "the second batch raised the SEQUENCE of the first"
    );
}
