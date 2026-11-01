//! Scheduling through the management API and MCP: writes schedule only when the caller asks, MCP may not mail people
//! outside the organisation without the scope that says so, and invitations are answered with `respond` (PLAN 2.8,
//! 2.12).

use davhaven_testkit::davhaven_app::services::{
    DeleteEventOptions, InvitationResponse, ObjectRef, ObjectSelector, ScheduleStatus,
};
use davhaven_testkit::davhaven_domain::{ErrorKind, ExternalKey, PartStat, Scope, Uid};

use super::support::{Org, Person, World, event, partstat_in, property_in, write};

const GUEST: &str = "mailto:guest@example.net";

struct Fixture {
    world: World,
    acme: Org,
    anna: Person,
    ben: Person,
}

async fn fixture() -> Fixture {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    Fixture { world, acme, anna, ben }
}

#[tokio::test]
async fn an_api_write_schedules_only_when_the_caller_asks() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let ctx = world.api(&acme, &anna, &[Scope::EventsWrite, Scope::EventsRead]);
    let calendar = world.collection(&acme, &anna, "personal");

    let quiet = world
        .services
        .objects
        .put_event(
            &ctx,
            &calendar,
            write("k1", &event("Quiet", &anna, &[&ben.mailto()]), false),
        )
        .await
        .unwrap();
    assert!(quiet.created);
    assert!(!quiet.schedule.is_scheduled());
    assert_eq!(world.inbox(&acme, &ben).await.len(), 0, "nobody is told");
    assert!(world.copy_of(&acme, &ben, "k1").await.is_none());

    let loud = world
        .services
        .objects
        .put_event(
            &ctx,
            &calendar,
            write("k2", &event("Loud", &anna, &[&ben.mailto()]), true),
        )
        .await
        .unwrap();
    assert_eq!(loud.schedule.recipients.len(), 1);
    assert_eq!(loud.schedule.recipients[0].status, ScheduleStatus::Delivered);
    assert_eq!(world.inbox(&acme, &ben).await.len(), 1);
    assert!(
        world
            .objects_of(&acme, &ben)
            .await
            .iter()
            .any(|object| object.data.contains("SUMMARY:Loud"))
    );
}

#[tokio::test]
async fn deleting_through_the_api_cancels_only_when_asked() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let ctx = world.api(&acme, &anna, &[Scope::EventsWrite, Scope::EventsRead]);
    let calendar = world.collection(&acme, &anna, "personal");
    for key in ["a", "b"] {
        world
            .services
            .objects
            .put_event(&ctx, &calendar, write(key, &event(key, &anna, &[&ben.mailto()]), true))
            .await
            .unwrap();
    }
    let selector = |key: &str| ObjectSelector::Key(ExternalKey::parse(key).unwrap());
    world
        .services
        .objects
        .delete_event(&ctx, &calendar, &selector("a"), DeleteEventOptions::default())
        .await
        .unwrap();
    assert_eq!(
        world.inbox(&acme, &ben).await.len(),
        2,
        "no cancellation was sent for `a`"
    );
    world
        .services
        .objects
        .delete_event(
            &ctx,
            &calendar,
            &selector("b"),
            DeleteEventOptions {
                notify_attendees: true,
                ..DeleteEventOptions::default()
            },
        )
        .await
        .unwrap();
    let inbox = world.inbox(&acme, &ben).await;
    assert_eq!(inbox.len(), 3);
    assert_eq!(
        property_in(&inbox.last().unwrap().data, "METHOD").as_deref(),
        Some("CANCEL")
    );
}

#[tokio::test]
async fn mcp_may_mail_external_guests_only_with_the_scope_that_says_so() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let calendar = world.collection(&acme, &anna, "personal");
    let without = world.mcp(&acme, &anna, &[Scope::McpWrite, Scope::McpRead]);
    let with = world.mcp(
        &acme,
        &anna,
        &[Scope::McpWrite, Scope::McpRead, Scope::McpScheduleExternal],
    );

    // Colleagues are fine without the scope.
    world
        .services
        .objects
        .put_event(
            &without,
            &calendar,
            write("inside", &event("Inside", &anna, &[&ben.mailto()]), true),
        )
        .await
        .unwrap();
    assert_eq!(world.inbox(&acme, &ben).await.len(), 1);

    // Guests are not, and the refusal stores nothing.
    let error = world
        .services
        .objects
        .put_event(
            &without,
            &calendar,
            write("outside", &event("Outside", &anna, &[GUEST]), true),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    assert_eq!(world.mail_jobs(&acme).await.len(), 0);
    assert!(
        !world
            .objects_of(&acme, &anna)
            .await
            .iter()
            .any(|object| object.data.contains("SUMMARY:Outside"))
    );

    // With the scope and `notify_attendees` the guest is mailed.
    let outcome = world
        .services
        .objects
        .put_event(
            &with,
            &calendar,
            write("outside", &event("Outside", &anna, &[GUEST]), true),
        )
        .await
        .unwrap();
    assert_eq!(outcome.schedule.recipients[0].status, ScheduleStatus::ImipSent);
    assert_eq!(world.mail_jobs(&acme).await.len(), 1);
    assert!(world.audit_actions(&acme).await.contains(&"mcp.write".to_owned()));
}

/// The stored text of the event of `anna` that is called `Review`.
async fn review_text(world: &World, acme: &Org, anna: &Person) -> String {
    world
        .objects_of(acme, anna)
        .await
        .into_iter()
        .find(|object| object.data.contains("SUMMARY:Review"))
        .map(|object| object.data)
        .unwrap_or_default()
}

#[tokio::test]
async fn removing_a_guest_with_null_or_a_shorter_list_is_mail_to_them_and_follows_the_rules_of_mail() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let calendar = world.collection(&acme, &anna, "personal");
    let without = world.mcp(&acme, &anna, &[Scope::McpWrite, Scope::McpRead]);
    let with = world.mcp(
        &acme,
        &anna,
        &[Scope::McpWrite, Scope::McpRead, Scope::McpScheduleExternal],
    );
    // The guest and a colleague are on the event and nobody was told (`notify_attendees` was off).
    let invited = event("Review", &anna, &[GUEST, &ben.mailto()]);
    world
        .services
        .objects
        .put_event(&with, &calendar, write("review", &invited, false))
        .await
        .unwrap();
    assert_eq!(world.mail_jobs(&acme).await.len(), 0);

    // Taking the guest off the event is a message to a person outside the tenant: a token without the scope is
    // refused, and the refusal stores nothing and sends nothing.
    let drop_guest = serde_json::json!({"attendees": [{"address": ben.mailto()}]});
    let error = world
        .services
        .objects
        .put_event(&without, &calendar, write("review", &drop_guest, true))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    assert_eq!(world.mail_jobs(&acme).await.len(), 0, "a refused write sends nothing");
    assert_eq!(
        super::support::count_of(&review_text(&world, &acme, &anna).await, "ATTENDEE"),
        2,
        "and changes nothing"
    );

    // With the scope and `notify_attendees` the guest is told that the event is cancelled for them.
    world
        .services
        .objects
        .put_event(&with, &calendar, write("review", &drop_guest, true))
        .await
        .unwrap();
    assert_eq!(
        world.mail_jobs(&acme).await,
        vec![("mailto:guest@example.net".to_owned(), "CANCEL".to_owned())],
        "the guest is cancelled by mail, the colleague is told through the inbox"
    );
    let text = review_text(&world, &acme, &anna).await;
    assert_eq!(super::support::count_of(&text, "ATTENDEE"), 1, "{text}");

    // `attendees: null` takes everybody off the event. The only person outside the tenant is gone already, so no
    // scope is needed for it.
    world
        .services
        .objects
        .put_event(
            &without,
            &calendar,
            write("review", &serde_json::json!({"attendees": null}), true),
        )
        .await
        .unwrap();
    let text = review_text(&world, &acme, &anna).await;
    assert_eq!(super::support::count_of(&text, "ATTENDEE"), 0, "{text}");

    // The same `null` over an event whose guest is still on it is mail to the outside, and is refused without the
    // scope like the shorter list is: nothing is stored and nothing is sent.
    world
        .services
        .objects
        .put_event(
            &with,
            &calendar,
            write("again", &event("Again", &anna, &[GUEST]), false),
        )
        .await
        .unwrap();
    let jobs = world.mail_jobs(&acme).await.len();
    let error = world
        .services
        .objects
        .put_event(
            &without,
            &calendar,
            write("again", &serde_json::json!({"attendees": null}), true),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    assert_eq!(
        world.mail_jobs(&acme).await.len(),
        jobs,
        "a refused write sends nothing"
    );
}

#[tokio::test]
async fn the_organizer_of_an_event_with_attendees_cannot_be_removed_with_null() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let ctx = world.api(&acme, &anna, &[Scope::EventsWrite, Scope::EventsRead]);
    let calendar = world.collection(&acme, &anna, "personal");
    world
        .services
        .objects
        .put_event(
            &ctx,
            &calendar,
            write("review", &event("Review", &anna, &[&ben.mailto()]), false),
        )
        .await
        .unwrap();
    let before = world.objects_of(&acme, &anna).await;

    // An event with attendees names its organizer: the write is refused as invalid, and nothing is stored.
    let error = world
        .services
        .objects
        .put_event(
            &ctx,
            &calendar,
            write("review", &serde_json::json!({"organizer": null}), false),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Invalid);
    assert_eq!(world.objects_of(&acme, &anna).await, before);

    // The attendees go with it in one write.
    world
        .services
        .objects
        .put_event(
            &ctx,
            &calendar,
            write(
                "review",
                &serde_json::json!({"organizer": null, "attendees": null}),
                false,
            ),
        )
        .await
        .unwrap();
    let text = world.objects_of(&acme, &anna).await.remove(0).data;
    assert!(
        !text.contains("ORGANIZER") && !text.contains("ATTENDEE"),
        "an event nobody is invited to has no organizer: {text}"
    );
}
#[tokio::test]
async fn an_invitation_is_answered_through_the_api_and_the_organizer_hears_it() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let anna_ctx = world.dav(&acme, &anna);
    world
        .put(
            &anna_ctx,
            &world.object(&acme, &anna, "m-1.ics"),
            &super::support::meeting("m-1", &anna, &[&ben.mailto()]).build(),
        )
        .await
        .unwrap();
    let ben_ctx = world.api(&acme, &ben, &[Scope::EventsWrite, Scope::EventsRead]);
    let target = ObjectRef {
        calendar: world.collection(&acme, &ben, "personal"),
        object: ObjectSelector::Uid(Uid::parse("m-1").unwrap()),
    };

    let view = world
        .services
        .scheduling
        .respond(
            &ben_ctx,
            target.clone(),
            InvitationResponse {
                partstat: PartStat::Tentative,
                comment: Some("Maybe, depends on the train".to_owned()),
            },
        )
        .await
        .unwrap();

    assert_eq!(
        view.data
            .attendees
            .as_ref()
            .and_then(|list| list.first())
            .and_then(|attendee| attendee.partstat),
        Some(PartStat::Tentative)
    );
    let organizer_copy = world.text(&anna_ctx, &world.object(&acme, &anna, "m-1.ics")).await;
    assert_eq!(
        partstat_in(&organizer_copy, &ben.mailto()),
        Some(PartStat::Tentative),
        "{organizer_copy}"
    );
    let inbox = world.inbox(&acme, &anna).await;
    assert_eq!(inbox.len(), 1);
    assert!(
        inbox[0].data.contains("COMMENT:Maybe\\, depends on the train"),
        "{}",
        inbox[0].data
    );

    // Answering again with the same answer changes and sends nothing.
    world
        .services
        .scheduling
        .respond(
            &ben_ctx,
            target,
            InvitationResponse {
                partstat: PartStat::Tentative,
                comment: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(world.inbox(&acme, &anna).await.len(), 1);
}

#[tokio::test]
async fn respond_has_its_own_rules_for_who_scope_and_input() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let cara = world.user(&acme, "cara").await;
    let anna_ctx = world.dav(&acme, &anna);
    world
        .put(
            &anna_ctx,
            &world.object(&acme, &anna, "m-1.ics"),
            &super::support::meeting("m-1", &anna, &[&ben.mailto()]).build(),
        )
        .await
        .unwrap();
    let uid = || ObjectSelector::Uid(Uid::parse("m-1").unwrap());
    let accept = || InvitationResponse {
        partstat: PartStat::Accepted,
        comment: None,
    };

    // The organizer is not an attendee of their own event: it is visible to them and not theirs to answer.
    let own = ObjectRef {
        calendar: world.collection(&acme, &anna, "personal"),
        object: uid(),
    };
    let error = world
        .services
        .scheduling
        .respond(&world.api(&acme, &anna, &[Scope::EventsWrite]), own.clone(), accept())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    // A tenant token sees the calendar (it may read events) but is nobody who is invited.
    let error = world
        .services
        .scheduling
        .respond(&world.tenant_token(&acme, &[Scope::EventsWrite]), own, accept())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);

    // Somebody who is not invited has no such event.
    let ben_copy = ObjectRef {
        calendar: world.collection(&acme, &ben, "personal"),
        object: uid(),
    };
    let error = world
        .services
        .scheduling
        .respond(
            &world.api(&acme, &cara, &[Scope::EventsWrite]),
            ben_copy.clone(),
            accept(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound, "Ben's calendar is invisible to Cara");

    // A token without the write scope may not answer.
    let error = world
        .services
        .scheduling
        .respond(
            &world.api(&acme, &ben, &[Scope::EventsRead]),
            ben_copy.clone(),
            accept(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);

    // DAV has no such operation.
    let error = world
        .services
        .scheduling
        .respond(&world.dav(&acme, &ben), ben_copy.clone(), accept())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound);

    // Only the three answers of an attendee, and a remark of at most 500 characters.
    let ben_ctx = world.api(&acme, &ben, &[Scope::EventsWrite]);
    for response in [
        InvitationResponse {
            partstat: PartStat::NeedsAction,
            comment: None,
        },
        InvitationResponse {
            partstat: PartStat::Delegated,
            comment: None,
        },
        InvitationResponse {
            partstat: PartStat::Accepted,
            comment: Some("x".repeat(501)),
        },
    ] {
        let error = world
            .services
            .scheduling
            .respond(&ben_ctx, ben_copy.clone(), response)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid);
    }
    assert_eq!(
        world.inbox(&acme, &anna).await.len(),
        0,
        "none of that reached the organizer"
    );

    // MCP answers too, with its own scope.
    let mcp = world.mcp(&acme, &ben, &[Scope::McpWrite]);
    world
        .services
        .scheduling
        .respond(&mcp, ben_copy, accept())
        .await
        .unwrap();
    assert_eq!(world.inbox(&acme, &anna).await.len(), 1);
    assert!(world.audit_actions(&acme).await.contains(&"mcp.write".to_owned()));
}

#[tokio::test]
async fn an_answer_to_an_external_organizer_is_mailed_with_the_remark() {
    let world = World::with(|deps| deps.config.scheduling.inbound_itip.enabled = true);
    let acme = world
        .org_with("acme", |settings| {
            settings.scheduling.inbound_methods = vec![
                davhaven_testkit::davhaven_domain::ItipMethod::Reply,
                davhaven_testkit::davhaven_domain::ItipMethod::Request,
            ];
        })
        .await;
    let ben = world.user(&acme, "ben").await;
    let request = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Other//EN\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:ext-1\r\n\
        DTSTAMP:20270101T000000Z\r\nDTSTART:20270310T090000Z\r\nDTEND:20270310T100000Z\r\nSUMMARY:Their meeting\r\n\
        ORGANIZER:mailto:olga@example.net\r\nATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:ben@acme.example\r\n\
        END:VEVENT\r\nEND:VCALENDAR\r\n";
    world
        .services
        .scheduling
        .inbound_itip(
            &world.gateway(&acme),
            davhaven_testkit::davhaven_wire::InboundItipRequest {
                message_id: "<req-1@example.net>".to_owned(),
                from: davhaven_testkit::davhaven_domain::Email::parse("olga@example.net").unwrap(),
                ical: request.to_owned(),
                dmarc: davhaven_testkit::davhaven_wire::AuthVerdict::Pass,
                dkim: davhaven_testkit::davhaven_wire::AuthVerdict::Pass,
            },
        )
        .await
        .unwrap();
    assert!(world.copy_of(&acme, &ben, "ext-1").await.is_some());

    world
        .services
        .scheduling
        .respond(
            &world.api(&acme, &ben, &[Scope::EventsWrite]),
            ObjectRef {
                calendar: world.collection(&acme, &ben, "personal"),
                object: ObjectSelector::Uid(Uid::parse("ext-1").unwrap()),
            },
            InvitationResponse {
                partstat: PartStat::Declined,
                comment: Some("Clash with another meeting".to_owned()),
            },
        )
        .await
        .unwrap();
    world.run_outbox().await;
    let mails = world.mails_to("olga@example.net").await;
    assert_eq!(mails.len(), 1);
    let (method, ics) = super::support::calendar_of(&mails[0].mail);
    assert_eq!(method, "REPLY");
    assert!(ics.contains("COMMENT:Clash with another meeting"), "{ics}");
    assert_eq!(partstat_in(&ics, "mailto:ben@acme.example"), Some(PartStat::Declined));
    assert!(
        mails[0].mail.text.contains("Clash with another meeting"),
        "the mail shows the remark"
    );
}

#[tokio::test]
async fn a_tenant_token_cannot_ask_for_attendees_to_be_notified_but_can_write_without_asking() {
    let Fixture { world, acme, anna, ben } = fixture().await;
    let team = world.group(&acme, "team", &[&anna, &ben]).await;
    world
        .calendar(
            &acme,
            &team,
            "shared",
            davhaven_testkit::davhaven_domain::CalendarKind::Group,
        )
        .await;
    let ctx = world.tenant_token(&acme, &[Scope::EventsWrite, Scope::EventsRead]);
    let calendar = world.collection(&acme, &team, "shared");

    // Invitations go out in the name of a person: a token that is nobody cannot send them, and is told so.
    let error = world
        .services
        .objects
        .put_event(
            &ctx,
            &calendar,
            write("k1", &event("Meeting", &anna, &[&ben.mailto()]), true),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Invalid);
    assert_eq!(world.inbox(&acme, &ben).await.len(), 0);
    assert!(
        world.objects_of(&acme, &team).await.is_empty(),
        "the refused write stored nothing"
    );

    // Without asking, the event is stored and nobody is told.
    let outcome = world
        .services
        .objects
        .put_event(
            &ctx,
            &calendar,
            write("k1", &event("Meeting", &anna, &[&ben.mailto()]), false),
        )
        .await
        .unwrap();
    assert!(!outcome.schedule.is_scheduled());
    assert_eq!(world.objects_of(&acme, &team).await.len(), 1);
}
