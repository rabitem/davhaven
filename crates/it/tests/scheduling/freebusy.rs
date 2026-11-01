//! Free-busy, the scheduling outbox, the search for free slots and the scheduling inbox (PLAN 2.8, 2.6).

use chrono::{DateTime, NaiveTime, TimeZone, Utc};
use davhaven_testkit::davhaven_app::services::{
    BusyKind, BusyPeriod, FindSlotsRequest, FreeBusyRequest, FreeBusyTarget, RecipientResponse, ScheduleStatus,
    TimeRange,
};
use davhaven_testkit::davhaven_domain::{
    CalendarUserAddress, Classification, ErrorKind, EventStatus, Precondition, ResourcePath, Scope, TimeZoneName,
    Transparency,
};
use davhaven_testkit::davhaven_fixtures::event::{EventBuilder, When};
use davhaven_testkit::davhaven_wire::mcp::WorkingHours;

use super::support::{Org, Person, World, meeting, property_in};

fn at(hour: u32, minute: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 3, 10, hour, minute, 0).unwrap()
}

fn day() -> TimeRange {
    TimeRange::new(Some(at(0, 0)), Some(at(0, 0) + chrono::Duration::days(1)))
}

fn address(text: &str) -> CalendarUserAddress {
    CalendarUserAddress::parse(text).unwrap()
}

/// Puts an event without attendees into the personal calendar of `person`.
async fn busy(
    world: &World,
    org: &Org,
    person: &Person,
    uid: &str,
    from: (u32, u32),
    to: (u32, u32),
    edit: impl FnOnce(EventBuilder) -> EventBuilder,
) {
    let builder = EventBuilder::event(uid)
        .summary("Busy")
        .starts(When::utc(2027, 3, 10, from.0, from.1))
        .ends(When::utc(2027, 3, 10, to.0, to.1));
    world
        .put(
            &world.dav(org, person),
            &world.object(org, person, &format!("{uid}.ics")),
            &edit(builder).build(),
        )
        .await
        .unwrap();
}

struct Office {
    world: World,
    acme: Org,
    anna: Person,
    ben: Person,
    cara: Person,
}

async fn office() -> Office {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let cara = world.user(&acme, "cara").await;
    // Ben is busy 09:00-10:00 (a private appointment counts like any other); Cara has a tentative hour at 11:00 and an
    // event that leaves her free (`TRANSP:TRANSPARENT`) at 09:00.
    busy(&world, &acme, &ben, "b1", (9, 0), (10, 0), |event| {
        event.class(Classification::Private)
    })
    .await;
    busy(&world, &acme, &cara, "c1", (11, 0), (12, 0), |event| {
        event.status(EventStatus::Tentative)
    })
    .await;
    busy(&world, &acme, &cara, "c2", (9, 0), (10, 0), |event| {
        event.transp(Transparency::Transparent)
    })
    .await;
    Office {
        world,
        acme,
        anna,
        ben,
        cara,
    }
}

#[tokio::test]
async fn the_busy_time_of_people_says_when_and_never_why() {
    let Office {
        world,
        acme,
        anna,
        ben,
        cara,
    } = office().await;
    let globex = world.org("globex").await;
    let dana = world.user(&globex, "dana").await;
    let team = world.group(&acme, "team", &[&anna]).await;
    busy(&world, &globex, &dana, "d1", (9, 0), (10, 0), |event| event).await;

    let asked = vec![
        ben.address(),
        cara.address(),
        dana.address(),
        address("mailto:nobody@acme.example"),
        address(&format!("/dav/principals/acme/{}/", team.name)),
    ];
    let result = world
        .services
        .scheduling
        .free_busy(
            &world.dav(&acme, &anna),
            FreeBusyRequest {
                target: FreeBusyTarget::Addresses(asked.clone()),
                range: day(),
            },
        )
        .await
        .unwrap();

    assert_eq!(result.range, day());
    let known: Vec<bool> = result.entries.iter().map(|entry| entry.known).collect();
    assert_eq!(
        known,
        vec![true, true, false, false, false],
        "other tenants, strangers and groups have no busy time to give"
    );
    let named: Vec<Option<CalendarUserAddress>> = result.entries.iter().map(|entry| entry.address.clone()).collect();
    assert_eq!(
        named,
        asked.into_iter().map(Some).collect::<Vec<_>>(),
        "in the order of the request"
    );
    assert_eq!(
        result.entries[0].periods,
        vec![BusyPeriod {
            start: at(9, 0),
            end: at(10, 0),
            kind: BusyKind::Busy
        }],
        "a private appointment is busy time, and nothing more is said"
    );
    assert_eq!(
        result.entries[1].periods,
        vec![BusyPeriod {
            start: at(11, 0),
            end: at(12, 0),
            kind: BusyKind::BusyTentative
        }],
        "a transparent event does not count, a tentative one is tentative"
    );
    assert!(result.entries[2..].iter().all(|entry| entry.periods.is_empty()));
}

#[tokio::test]
async fn null_for_the_transparency_makes_a_free_event_busy_again() {
    use davhaven_testkit::davhaven_app::services::{EventWrite, ObjectSelector};
    use davhaven_testkit::davhaven_domain::{EventData, EventField, Uid};
    use davhaven_testkit::davhaven_wire::EventView;
    use davhaven_testkit::davhaven_wire::mcp::ChangeScope;

    let Office {
        world,
        acme,
        anna,
        cara,
        ..
    } = office().await;
    let busy_of_cara = || async {
        world
            .services
            .scheduling
            .free_busy(
                &world.dav(&acme, &anna),
                FreeBusyRequest {
                    target: FreeBusyTarget::Addresses(vec![cara.address()]),
                    range: day(),
                },
            )
            .await
            .unwrap()
            .entries[0]
            .periods
            .clone()
    };
    // `c2` at 09:00 leaves her free (`TRANSP:TRANSPARENT`): only the tentative hour at 11:00 counts.
    assert_eq!(
        busy_of_cara().await,
        vec![BusyPeriod {
            start: at(11, 0),
            end: at(12, 0),
            kind: BusyKind::BusyTentative
        }]
    );
    // The client of her integration says "no transparency" with null: the property goes, and the default is busy.
    let ctx = world.api(&acme, &cara, &[Scope::EventsRead, Scope::EventsWrite]);
    world
        .services
        .objects
        .put_event(
            &ctx,
            &world.collection(&acme, &cara, "personal"),
            EventWrite {
                target: Some(ObjectSelector::Uid(Uid::parse("c2").unwrap())),
                event: EventView::from_data(EventData::default().without(EventField::Transparency)),
                notify_attendees: false,
                if_match: None,
                scope: ChangeScope::All,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        busy_of_cara().await,
        vec![
            BusyPeriod {
                start: at(9, 0),
                end: at(10, 0),
                kind: BusyKind::Busy
            },
            BusyPeriod {
                start: at(11, 0),
                end: at(12, 0),
                kind: BusyKind::BusyTentative
            },
        ]
    );
}
#[tokio::test]
async fn free_busy_is_open_to_the_tenant_on_every_surface_that_has_it() {
    let Office {
        world, acme, anna, ben, ..
    } = office().await;
    let ask = || FreeBusyRequest {
        target: FreeBusyTarget::Addresses(vec![ben.address()]),
        range: day(),
    };

    for ctx in [
        world.dav(&acme, &anna),
        world.api(&acme, &anna, &[Scope::EventsRead]),
        world.mcp(&acme, &anna, &[Scope::McpRead]),
    ] {
        let result = world.services.scheduling.free_busy(&ctx, ask()).await.unwrap();
        assert_eq!(result.entries[0].periods.len(), 1, "{:?}", ctx.channel);
    }
    // A token needs the scope for reading, and a tenant token never reads a person's own time.
    for ctx in [
        world.api(&acme, &anna, &[Scope::EventsWrite]),
        world.mcp(&acme, &anna, &[Scope::McpWrite]),
        world.tenant_token(&acme, &[Scope::EventsRead]),
    ] {
        assert!(
            world.services.scheduling.free_busy(&ctx, ask()).await.is_err(),
            "{:?}",
            ctx.channel
        );
    }
}

#[tokio::test]
async fn ranges_must_be_bounded_and_reasonable() {
    let Office {
        world, acme, anna, ben, ..
    } = office().await;
    let ctx = world.dav(&acme, &anna);
    for range in [
        TimeRange::new(Some(at(0, 0)), None),
        TimeRange::new(None, Some(at(0, 0))),
        TimeRange::new(Some(at(5, 0)), Some(at(4, 0))),
        TimeRange::new(Some(at(0, 0)), Some(Utc.with_ymd_and_hms(2040, 1, 1, 0, 0, 0).unwrap())),
    ] {
        let error = world
            .services
            .scheduling
            .free_busy(
                &ctx,
                FreeBusyRequest {
                    target: FreeBusyTarget::Addresses(vec![ben.address()]),
                    range,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid, "{range:?}");
    }
}

#[tokio::test]
async fn the_free_busy_of_a_collection_is_read_through_its_path() {
    let Office { world, acme, ben, .. } = office().await;
    let path = ResourcePath::Collection {
        tenant: acme.slug.clone(),
        principal: ben.name.clone(),
        binding: davhaven_testkit::davhaven_domain::CalendarSlug::parse("personal").unwrap(),
    };
    let result = world
        .services
        .scheduling
        .free_busy(
            &world.dav(&acme, &ben),
            FreeBusyRequest {
                target: FreeBusyTarget::Collection(path.clone()),
                range: day(),
            },
        )
        .await
        .unwrap();
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].address, None);
    assert_eq!(result.entries[0].periods.len(), 1);

    // Another tenant does not see the collection at all.
    let globex = world.org("globex").await;
    let dana = world.user(&globex, "dana").await;
    let error = world
        .services
        .scheduling
        .free_busy(
            &world.dav(&globex, &dana),
            FreeBusyRequest {
                target: FreeBusyTarget::Collection(path),
                range: day(),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound);
}

const REQUEST: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Client//EN\r\nMETHOD:REQUEST\r\nBEGIN:VFREEBUSY\r\n\
    UID:fb-1\r\nDTSTAMP:20270301T090000Z\r\nDTSTART:20270310T000000Z\r\nDTEND:20270311T000000Z\r\n\
    ORGANIZER:mailto:anna@acme.example\r\nATTENDEE:mailto:ben@acme.example\r\nATTENDEE:mailto:nobody@acme.example\r\n\
    END:VFREEBUSY\r\nEND:VCALENDAR\r\n";

#[tokio::test]
async fn a_free_busy_request_in_the_outbox_is_answered_per_attendee() {
    let Office {
        world, acme, anna, ben, ..
    } = office().await;
    let response = world
        .services
        .scheduling
        .outbox_post(&world.dav(&acme, &anna), &anna.name, REQUEST.to_owned())
        .await
        .unwrap();

    let statuses: Vec<(String, ScheduleStatus)> = response
        .responses
        .iter()
        .map(|entry: &RecipientResponse| (entry.recipient.as_str().to_owned(), entry.status))
        .collect();
    assert_eq!(
        statuses,
        vec![
            (ben.mailto(), ScheduleStatus::Delivered),
            ("mailto:nobody@acme.example".to_owned(), ScheduleStatus::UnknownAddress)
        ]
    );
    let data = response.responses[0].calendar_data.as_deref().expect("Ben's busy time");
    assert_eq!(
        property_in(data, "METHOD").as_deref(),
        Some("REPLY"),
        "the answer is an iTIP REPLY that carries a VFREEBUSY (RFC 6638 section 5)"
    );
    assert!(
        data.contains("BEGIN:VFREEBUSY") && data.contains("20270310T090000Z/20270310T100000Z"),
        "{data}"
    );
    assert!(
        !data.contains("SUMMARY") && !data.contains("DESCRIPTION"),
        "never why: {data}"
    );
    assert_eq!(response.responses[1].calendar_data, None);
}

#[tokio::test]
async fn the_outbox_takes_nothing_but_the_free_busy_request_of_its_owner() {
    let Office {
        world, acme, anna, ben, ..
    } = office().await;
    let ctx = world.dav(&acme, &anna);

    // The ORGANIZER must be the owner of the outbox.
    let error = world
        .services
        .scheduling
        .outbox_post(&ctx, &anna.name, REQUEST.replace("mailto:anna@", "mailto:ben@"))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    assert_eq!(error.precondition(), Some(&Precondition::OrganizerAllowed));

    // Invitations are not posted, they happen when the organizer's copy is written; nothing else is accepted either.
    let invitation = meeting("m-1", &anna, &[&ben.mailto()]).build();
    for body in [
        invitation,
        REQUEST.replace("METHOD:REQUEST", "METHOD:REPLY"),
        REQUEST.replace("VFREEBUSY", "VEVENT"),
        "not iCalendar at all".to_owned(),
    ] {
        let error = world
            .services
            .scheduling
            .outbox_post(&ctx, &anna.name, body)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid);
    }

    // Somebody else's outbox does not exist for Anna; the API has no outbox.
    let error = world
        .services
        .scheduling
        .outbox_post(&ctx, &ben.name, REQUEST.to_owned())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound);
    let error = world
        .services
        .scheduling
        .outbox_post(
            &world.api(&acme, &anna, &[Scope::EventsWrite]),
            &anna.name,
            REQUEST.to_owned(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound);
    assert_eq!(world.mail_jobs(&acme).await.len(), 0);
    assert_eq!(world.inbox(&acme, &ben).await.len(), 0);
}

fn slots_request(addresses: Vec<CalendarUserAddress>, minutes: u32) -> FindSlotsRequest {
    FindSlotsRequest {
        addresses,
        range: TimeRange::new(Some(at(8, 0)), Some(at(14, 0))),
        duration_minutes: minutes,
        working_hours: None,
        time_zone: None,
        limit: None,
    }
}

#[tokio::test]
async fn free_slots_are_where_everybody_is_free() {
    let Office {
        world,
        acme,
        anna,
        ben,
        cara,
    } = office().await;
    let ctx = world.dav(&acme, &anna);
    // Ben is busy 09:00-10:00 and Cara (tentatively) 11:00-12:00; her transparent event does not count.
    let found = world
        .services
        .scheduling
        .find_free_slots(&ctx, slots_request(vec![ben.address(), cara.address()], 60))
        .await
        .unwrap();
    let starts: Vec<DateTime<Utc>> = found.slots.iter().map(|slot| slot.start).collect();
    assert_eq!(starts, vec![at(8, 0), at(10, 0), at(12, 0), at(13, 0)]);
    assert!(
        found
            .slots
            .iter()
            .all(|slot| slot.end - slot.start == chrono::Duration::hours(1))
    );
    assert!(!found.truncated);

    // The most slots, earliest first, and the caller learns that there were more.
    let mut limited = slots_request(vec![ben.address(), cara.address()], 30);
    limited.limit = Some(3);
    let found = world.services.scheduling.find_free_slots(&ctx, limited).await.unwrap();
    assert_eq!(found.slots.len(), 3);
    assert!(found.truncated);
    assert_eq!(found.slots[0].start, at(8, 0));

    // Working hours in a time zone: 09:00-17:00 in Berlin (UTC+1 on that day) is 08:00-16:00 UTC, clipped to the range.
    let mut working = slots_request(vec![ben.address()], 60);
    working.working_hours = Some(WorkingHours {
        start: NaiveTime::from_hms_opt(11, 0, 0).unwrap(),
        end: NaiveTime::from_hms_opt(13, 0, 0).unwrap(),
    });
    working.time_zone = Some(TimeZoneName::parse("Europe/Berlin").unwrap());
    let found = world.services.scheduling.find_free_slots(&ctx, working).await.unwrap();
    let starts: Vec<DateTime<Utc>> = found.slots.iter().map(|slot| slot.start).collect();
    assert_eq!(
        starts,
        vec![at(10, 0), at(11, 0)],
        "11:00-13:00 in Berlin is 10:00-12:00 UTC"
    );
}

#[tokio::test]
async fn the_search_for_free_slots_checks_its_input() {
    let Office {
        world, acme, anna, ben, ..
    } = office().await;
    let ctx = world.dav(&acme, &anna);
    let service = &world.services.scheduling;

    for minutes in [0, 24 * 60 + 1] {
        let error = service
            .find_free_slots(&ctx, slots_request(vec![ben.address()], minutes))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid, "{minutes} minutes");
    }
    let error = service
        .find_free_slots(&ctx, slots_request(Vec::new(), 30))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Invalid, "nobody to ask");
    let error = service
        .find_free_slots(
            &ctx,
            slots_request(vec![ben.address(), address("mailto:nobody@acme.example")], 30),
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.kind(),
        ErrorKind::Invalid,
        "every address must be a person of this organisation"
    );
    let mut unbounded = slots_request(vec![ben.address()], 30);
    unbounded.range = TimeRange::new(Some(at(8, 0)), None);
    assert_eq!(
        service.find_free_slots(&ctx, unbounded).await.unwrap_err().kind(),
        ErrorKind::Invalid
    );
    let mut too_many = slots_request(vec![ben.address()], 30);
    too_many.limit = Some(0);
    assert_eq!(
        service.find_free_slots(&ctx, too_many).await.unwrap_err().kind(),
        ErrorKind::Invalid
    );
}

#[tokio::test]
async fn the_inbox_belongs_to_its_principal_alone() {
    let Office {
        world,
        acme,
        anna,
        ben,
        cara,
    } = office().await;
    world
        .put(
            &world.dav(&acme, &anna),
            &world.object(&acme, &anna, "m-1.ics"),
            &meeting("m-1", &anna, &[&ben.mailto()]).build(),
        )
        .await
        .unwrap();
    let service = &world.services.scheduling;
    let ben_ctx = world.dav(&acme, &ben);

    let items = service.inbox_list(&ben_ctx, &ben.name).await.unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].data, None, "listings carry no data");
    let item = service.inbox_get(&ben_ctx, &items[0].path).await.unwrap();
    assert_eq!(
        property_in(item.data.as_deref().unwrap(), "METHOD").as_deref(),
        Some("REQUEST")
    );
    assert_eq!(item.etag, items[0].etag);

    // Nobody else sees it: not a colleague, not the organizer, not somebody of another tenant, not a token.
    let globex = world.org("globex").await;
    let dana = world.user(&globex, "dana").await;
    for (who, ctx) in [
        ("a colleague", world.dav(&acme, &cara)),
        ("the organizer", world.dav(&acme, &anna)),
        ("another tenant", world.dav(&globex, &dana)),
    ] {
        assert_eq!(
            service.inbox_list(&ctx, &ben.name).await.unwrap_err().kind(),
            ErrorKind::NotFound,
            "{who}"
        );
        assert_eq!(
            service.inbox_get(&ctx, &items[0].path).await.unwrap_err().kind(),
            ErrorKind::NotFound,
            "{who}"
        );
        assert_eq!(
            service.inbox_delete(&ctx, &items[0].path).await.unwrap_err().kind(),
            ErrorKind::NotFound,
            "{who}"
        );
    }
    let api = world.api(&acme, &ben, &[Scope::EventsRead, Scope::EventsWrite]);
    assert_eq!(
        service.inbox_list(&api, &ben.name).await.unwrap_err().kind(),
        ErrorKind::NotFound,
        "no inbox on the API"
    );

    // Ben removes the item.
    service.inbox_delete(&ben_ctx, &items[0].path).await.unwrap();
    assert_eq!(service.inbox_list(&ben_ctx, &ben.name).await.unwrap().len(), 0);
    assert_eq!(
        service.inbox_get(&ben_ctx, &items[0].path).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
}

#[tokio::test]
async fn quarantined_messages_are_never_shown_to_clients() {
    let world = World::with_inbound();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    world
        .put(
            &world.dav(&acme, &anna),
            &world.object(&acme, &anna, "m-1.ics"),
            &meeting("m-1", &anna, &["mailto:guest@example.net"]).build(),
        )
        .await
        .unwrap();
    // A forged answer: the gateway reports a failed DMARC check.
    let mut forged = super::support::gateway_mail(
        "guest@example.net",
        "<forged@example.net>",
        &super::support::reply_ical(
            "m-1",
            &anna.mailto(),
            "mailto:guest@example.net",
            davhaven_testkit::davhaven_domain::PartStat::Accepted,
            0,
            None,
        ),
    );
    forged.dmarc = davhaven_testkit::davhaven_wire::AuthVerdict::Fail;
    world.inbound(&acme, forged).await.unwrap();

    let kept = world.quarantined(&acme, &anna).await;
    assert_eq!(kept.len(), 1);
    let ctx = world.dav(&acme, &anna);
    assert_eq!(
        world
            .services
            .scheduling
            .inbox_list(&ctx, &anna.name)
            .await
            .unwrap()
            .len(),
        0
    );
    let path = ResourcePath::InboxItem {
        tenant: acme.slug.clone(),
        principal: anna.name.clone(),
        uri: kept[0].uri.clone(),
    };
    assert_eq!(
        world
            .services
            .scheduling
            .inbox_get(&ctx, &path)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        world
            .services
            .scheduling
            .inbox_delete(&ctx, &path)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
}
