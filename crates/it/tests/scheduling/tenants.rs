//! A request in one tenant never reaches what another tenant holds (R4): the scheduling operations answer as if it did
//! not exist, and nothing changes there.

use davhaven_testkit::davhaven_app::services::{CsrfToken, InvitationResponse, ObjectRef, ObjectSelector, RsvpAnswer};
use davhaven_testkit::davhaven_domain::{ErrorKind, PartStat, Scope, Uid};

use super::support::{World, gateway_mail, meeting, partstat_in, reply_ical};

const GUEST: &str = "mailto:guest@example.net";

const FREE_BUSY_REQUEST: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Client//EN\r\nMETHOD:REQUEST\r\n\
    BEGIN:VFREEBUSY\r\nUID:fb-1\r\nDTSTAMP:20270301T090000Z\r\nDTSTART:20270310T080000Z\r\nDTEND:20270310T180000Z\r\n\
    ORGANIZER:mailto:anna@acme.example\r\nATTENDEE:mailto:ben@acme.example\r\nEND:VFREEBUSY\r\nEND:VCALENDAR\r\n";

#[tokio::test]
async fn the_scheduling_operations_of_one_tenant_do_not_reach_across_to_another() {
    let world = World::with_inbound();
    let acme = world.org("acme").await;
    let globex = world.org("globex").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    // Principals of the other tenant with names of the first one and with their own.
    let globex_anna = world.user(&globex, "anna").await;
    let dana = world.user(&globex, "dana").await;
    world
        .put(
            &world.dav(&acme, &anna),
            &world.object(&acme, &anna, "m-1.ics"),
            &meeting("m-1", &anna, &[&ben.mailto(), GUEST]).build(),
        )
        .await
        .unwrap();
    world.run_outbox().await;
    let organizer_path = world.object(&acme, &anna, "m-1.ics");
    let organizer_copy = world.text(&world.dav(&acme, &anna), &organizer_path).await;
    let acme_inbox = world.inbox(&acme, &anna).await.len();
    let acme_events = world.events(&acme).await.len();

    // `respond`: the calendar of Ben, and the UID of the event, do not exist in the other tenant.
    let ben_copy = ObjectRef {
        calendar: world.collection(&globex, &ben, "personal"),
        object: ObjectSelector::Uid(Uid::parse("m-1").unwrap()),
    };
    let error = world
        .services
        .scheduling
        .respond(
            &world.api(&globex, &dana, &[Scope::EventsWrite]),
            ben_copy,
            InvitationResponse {
                partstat: PartStat::Accepted,
                comment: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound, "respond");
    // The same names in the other tenant name other principals, and they have no such event.
    let error = world
        .services
        .scheduling
        .respond(
            &world.api(&globex, &dana, &[Scope::EventsWrite]),
            ObjectRef {
                calendar: world.collection(&globex, &globex_anna, "personal"),
                object: ObjectSelector::Uid(Uid::parse("m-1").unwrap()),
            },
            InvitationResponse {
                partstat: PartStat::Accepted,
                comment: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound, "respond, same names");

    // The outbox of a principal of the first tenant is not an outbox of the second.
    let error = world
        .services
        .scheduling
        .outbox_post(&world.dav(&globex, &dana), &ben.name, FREE_BUSY_REQUEST.to_owned())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound, "outbox");

    // A gateway of the second tenant forwarding an answer for an event of the first changes nothing there.
    let response = world
        .inbound(
            &globex,
            gateway_mail(
                "guest@example.net",
                "<cross-1@example.net>",
                &reply_ical("m-1", &anna.mailto(), GUEST, PartStat::Accepted, 0, None),
            ),
        )
        .await
        .unwrap();
    assert_eq!(response.reason.as_deref(), Some("unknown_event"), "inbound");
    assert!(
        world.quarantined(&acme, &anna).await.is_empty(),
        "nothing is kept in acme"
    );

    // An RSVP link of the first tenant does not open in the second.
    let object = world.copy_of(&acme, &anna, "m-1").await.unwrap();
    let token = world
        .rsvp_tokens(&acme, object.id)
        .await
        .pop()
        .expect("the guest has a link");
    let ctx = world.rsvp(&globex, &token);
    let error = world.services.scheduling.rsvp_page(&ctx).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound, "rsvp page");
    let error = world
        .services
        .scheduling
        .rsvp_answer(
            &ctx,
            RsvpAnswer {
                partstat: PartStat::Accepted,
                comment: None,
            },
            CsrfToken::new("v1.whatever"),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound, "rsvp answer");

    // And nothing changed in the first tenant.
    assert_eq!(
        world.text(&world.dav(&acme, &anna), &organizer_path).await,
        organizer_copy
    );
    assert_eq!(partstat_in(&organizer_copy, GUEST), Some(PartStat::NeedsAction));
    assert_eq!(world.inbox(&acme, &anna).await.len(), acme_inbox);
    assert_eq!(world.events(&acme).await.len(), acme_events);
}
