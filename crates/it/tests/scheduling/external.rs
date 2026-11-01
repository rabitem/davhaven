//! Scheduling with people outside the tenant: iMIP mail, the RSVP page and the policy that governs both (PLAN 2.8,
//! 2.13, 2.14).

use chrono::Duration;
use davhaven_testkit::davhaven_app::services::{CsrfToken, RecipientStatus, RsvpAnswer, ScheduleStatus};
use davhaven_testkit::davhaven_domain::{ErrorKind, EventType, ExternalPolicy, PartStat, RsvpToken};

use super::support::{
    Org, Person, World, calendar_of, count_of, csrf_of, meeting, partstat_in, property_in, status_in,
};

const GUEST: &str = "mailto:guest@example.net";

/// A world with the tenant `acme`, its organizer `anna` and an invitation to the guest.
struct Invited {
    world: World,
    acme: Org,
    anna: Person,
    token: RsvpToken,
}

async fn invited() -> Invited {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ctx = world.dav(&acme, &anna);
    world
        .put(
            &ctx,
            &world.object(&acme, &anna, "m-1.ics"),
            &meeting("m-1", &anna, &[GUEST]).build(),
        )
        .await
        .unwrap();
    world.run_outbox().await;
    let object = world.copy_of(&acme, &anna, "m-1").await.unwrap();
    let token = world
        .rsvp_tokens(&acme, object.id)
        .await
        .pop()
        .expect("the invitation carries an RSVP link");
    Invited {
        world,
        acme,
        anna,
        token,
    }
}

#[tokio::test]
async fn an_invitation_to_an_external_guest_is_mailed_once_with_an_rsvp_link() {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ctx = world.dav(&acme, &anna);
    let path = world.object(&acme, &anna, "m-1.ics");

    let outcome = world
        .put(&ctx, &path, &meeting("m-1", &anna, &[GUEST]).build())
        .await
        .unwrap();

    assert_eq!(
        outcome.schedule.recipients,
        vec![RecipientStatus {
            address: davhaven_testkit::davhaven_domain::CalendarUserAddress::parse(GUEST).unwrap(),
            status: ScheduleStatus::ImipSent
        }]
    );
    let stored = world.text(&ctx, &path).await;
    assert_eq!(status_in(&stored, GUEST).as_deref(), Some("1.1"), "{stored}");
    assert_eq!(
        world.mail_jobs(&acme).await,
        vec![(GUEST.to_owned(), "REQUEST".to_owned())]
    );
    assert_eq!(
        world.mails().await.len(),
        0,
        "nothing is sent inside the transaction of the write"
    );
    assert!(world.copy_of(&acme, &anna, "m-1").await.is_some());

    world.run_outbox().await;

    let mails = world.mails_to("guest@example.net").await;
    assert_eq!(mails.len(), 1, "one mail per external attendee");
    let mail = &mails[0].mail;
    let (method, ics) = calendar_of(mail);
    assert_eq!(method, "REQUEST");
    assert_eq!(property_in(&ics, "METHOD").as_deref(), Some("REQUEST"));
    assert_eq!(count_of(&ics, "ATTENDEE"), 1, "a guest sees only their own line: {ics}");
    assert!(
        !ics.contains("SCHEDULE-"),
        "no SCHEDULE-* parameter leaves the server: {ics}"
    );
    assert!(
        mail.text.contains("https://cal.example.org/rsvp/dvh_rsvp_"),
        "{}",
        mail.text
    );
    assert_eq!(
        mail.reply_to.as_ref().map(|reply| reply.address.as_str()),
        Some("anna@acme.example")
    );
    assert_eq!(mail.from.address.as_str(), "noreply@mail.example.org");
    let object = world.copy_of(&acme, &anna, "m-1").await.unwrap();
    assert_eq!(world.rsvp_tokens(&acme, object.id).await.len(), 1);
}

#[tokio::test]
async fn the_rsvp_page_shows_the_invitation_and_takes_an_answer_that_reaches_the_organizer() {
    let Invited {
        world,
        acme,
        anna,
        token,
    } = invited().await;
    let ctx = world.rsvp(&acme, &token);
    let page = world.services.scheduling.rsvp_page(&ctx).await.unwrap();
    assert!(page.html.contains("Planning"), "{}", page.html);
    assert!(page.html.contains("anna"), "the organizer's name is shown");
    assert!(!page.html.contains("anna@acme.example"), "never an address");
    let csrf = csrf_of(&page.html);

    let answered = world
        .services
        .scheduling
        .rsvp_answer(
            &ctx,
            RsvpAnswer {
                partstat: PartStat::Accepted,
                comment: Some("See you there".to_owned()),
            },
            CsrfToken::new(csrf),
        )
        .await
        .unwrap();
    assert!(answered.html.contains("Accepted"), "{}", answered.html);

    let organizer_copy = world
        .text(&world.dav(&acme, &anna), &world.object(&acme, &anna, "m-1.ics"))
        .await;
    assert_eq!(
        partstat_in(&organizer_copy, GUEST),
        Some(PartStat::Accepted),
        "{organizer_copy}"
    );
    // The remark is kept on the organizer's copy as CalendarServer's attendee comment (Calendar on macOS shows it next to the
    // guest), naming the guest and carrying the text, and the REPLY in the inbox carries it as `COMMENT`.
    let unfolded = organizer_copy.replace("\r\n ", "");
    let comment = unfolded
        .lines()
        .find(|line| line.starts_with("X-CALENDARSERVER-ATTENDEE-COMMENT"))
        .unwrap_or_else(|| panic!("the organizer's copy keeps the comment: {organizer_copy}"));
    assert!(
        comment.contains(GUEST) && comment.ends_with(":See you there"),
        "{comment}"
    );
    let inbox = world.inbox(&acme, &anna).await;
    assert_eq!(inbox.len(), 1);
    assert_eq!(property_in(&inbox[0].data, "METHOD").as_deref(), Some("REPLY"));
    assert!(inbox[0].data.contains("COMMENT:See you there"), "{}", inbox[0].data);
    let types = world.event_types(&acme).await;
    assert_eq!(
        types.iter().rev().take(4).rev().copied().collect::<Vec<_>>(),
        vec![
            EventType::CalendarObjectsChanged,
            EventType::CalendarObjectsChanged,
            EventType::SchedulingReplyReceived,
            EventType::RsvpAnswered
        ],
        "the invitation, the folded answer, the reply and the RSVP"
    );
    assert!(world.audit_actions(&acme).await.contains(&"rsvp.answered".to_owned()));
    let stored = world.rsvp_tokens(&acme, token.object_id).await.pop().unwrap();
    assert_eq!(stored.last_response, Some(PartStat::Accepted));
    assert!(stored.last_used_at.is_some());
}

#[tokio::test]
async fn an_answer_is_repeatable_and_a_repetition_tells_the_organizer_nothing_new() {
    let Invited {
        world,
        acme,
        anna,
        token,
    } = invited().await;
    let ctx = world.rsvp(&acme, &token);
    let csrf = csrf_of(&world.services.scheduling.rsvp_page(&ctx).await.unwrap().html);
    let answer = |partstat| RsvpAnswer {
        partstat,
        comment: None,
    };

    world
        .services
        .scheduling
        .rsvp_answer(&ctx, answer(PartStat::Accepted), CsrfToken::new(csrf.clone()))
        .await
        .unwrap();
    world
        .services
        .scheduling
        .rsvp_answer(&ctx, answer(PartStat::Accepted), CsrfToken::new(csrf.clone()))
        .await
        .unwrap();
    assert_eq!(
        world.inbox(&acme, &anna).await.len(),
        1,
        "the same answer twice is one message"
    );

    world
        .services
        .scheduling
        .rsvp_answer(&ctx, answer(PartStat::Declined), CsrfToken::new(csrf))
        .await
        .unwrap();
    let organizer_copy = world
        .text(&world.dav(&acme, &anna), &world.object(&acme, &anna, "m-1.ics"))
        .await;
    assert_eq!(partstat_in(&organizer_copy, GUEST), Some(PartStat::Declined));
    assert_eq!(world.inbox(&acme, &anna).await.len(), 2, "the changed mind is news");
    // The page now shows the current answer.
    let page = world.services.scheduling.rsvp_page(&ctx).await.unwrap();
    assert!(page.html.contains("Declined"), "{}", page.html);
}

#[tokio::test]
async fn a_form_that_cannot_be_used_is_shown_again_with_a_notice_and_records_nothing() {
    let Invited {
        world,
        acme,
        anna,
        token,
    } = invited().await;
    let ctx = world.rsvp(&acme, &token);
    let csrf = csrf_of(&world.services.scheduling.rsvp_page(&ctx).await.unwrap().html);
    let accepted = || RsvpAnswer {
        partstat: PartStat::Accepted,
        comment: None,
    };

    for bad in ["", "garbage", "v1.a.1.b"] {
        let page = world
            .services
            .scheduling
            .rsvp_answer(&ctx, accepted(), CsrfToken::new(bad))
            .await
            .unwrap();
        assert!(page.html.contains("was open for too long"), "{bad}: {}", page.html);
        assert!(page.html.contains("role=\"alert\""), "{bad}");
        assert!(
            page.html.contains("name=\"csrf\""),
            "{bad}: the form is there to try again"
        );
    }
    // The token of the page is good for one hour: afterwards the form comes back with a fresh token.
    world.clock.advance(Duration::minutes(61));
    let page = world
        .services
        .scheduling
        .rsvp_answer(&ctx, accepted(), CsrfToken::new(csrf.clone()))
        .await
        .unwrap();
    assert!(
        page.html.contains("was open for too long"),
        "an expired form: {}",
        page.html
    );
    let fresh = csrf_of(&page.html);
    assert_ne!(fresh, csrf, "the page that is shown again has a fresh token");

    for (partstat, comment, notice) in [
        (PartStat::NeedsAction, None, "Please choose one of the answers below"),
        (PartStat::Delegated, None, "Please choose one of the answers below"),
        (PartStat::Accepted, Some("x".repeat(501)), "Your comment is too long"),
    ] {
        let page = world
            .services
            .scheduling
            .rsvp_answer(&ctx, RsvpAnswer { partstat, comment }, CsrfToken::new(fresh.clone()))
            .await
            .unwrap();
        assert!(page.html.contains(notice), "{partstat:?}: {}", page.html);
    }
    let organizer_copy = world
        .text(&world.dav(&acme, &anna), &world.object(&acme, &anna, "m-1.ics"))
        .await;
    assert_eq!(
        partstat_in(&organizer_copy, GUEST),
        Some(PartStat::NeedsAction),
        "nothing was recorded"
    );
    assert_eq!(world.inbox(&acme, &anna).await.len(), 0);

    // The fresh token works.
    let answered = world
        .services
        .scheduling
        .rsvp_answer(&ctx, accepted(), CsrfToken::new(fresh))
        .await
        .unwrap();
    assert!(answered.html.contains("Accepted"), "{}", answered.html);
    assert_eq!(world.inbox(&acme, &anna).await.len(), 1);
}

#[tokio::test]
async fn the_csrf_token_of_one_link_is_useless_on_another() {
    let Invited {
        world,
        acme,
        anna,
        token,
    } = invited().await;
    // A second guest with a link of their own.
    let ctx = world.dav(&acme, &anna);
    world
        .put(
            &ctx,
            &world.object(&acme, &anna, "m-1.ics"),
            &meeting("m-1", &anna, &[GUEST, "mailto:other@example.net"]).build(),
        )
        .await
        .unwrap();
    world.run_outbox().await;
    let object = world.copy_of(&acme, &anna, "m-1").await.unwrap();
    let tokens = world.rsvp_tokens(&acme, object.id).await;
    let other = tokens
        .iter()
        .find(|row| row.attendee_address.as_str() == "mailto:other@example.net")
        .unwrap();
    let guest_ctx = world.rsvp(&acme, &token);
    let other_ctx = world.rsvp(&acme, other);
    let csrf_of_guest = csrf_of(&world.services.scheduling.rsvp_page(&guest_ctx).await.unwrap().html);
    let page = world
        .services
        .scheduling
        .rsvp_answer(
            &other_ctx,
            RsvpAnswer {
                partstat: PartStat::Accepted,
                comment: None,
            },
            CsrfToken::new(csrf_of_guest),
        )
        .await
        .unwrap();
    assert!(page.html.contains("could not be saved"), "{}", page.html);
    let organizer_copy = world
        .text(&world.dav(&acme, &anna), &world.object(&acme, &anna, "m-1.ics"))
        .await;
    assert_eq!(
        partstat_in(&organizer_copy, "mailto:other@example.net"),
        Some(PartStat::NeedsAction),
        "nothing was recorded for the other guest"
    );
}

#[tokio::test]
async fn links_stop_working_when_the_attendee_is_removed_the_event_is_cancelled_or_time_has_passed() {
    // Removing the attendee revokes the link and mails a cancellation.
    let Invited {
        world,
        acme,
        anna,
        token,
    } = invited().await;
    let anna_ctx = world.dav(&acme, &anna);
    let path = world.object(&acme, &anna, "m-1.ics");
    let ctx = world.rsvp(&acme, &token);
    assert!(world.services.scheduling.rsvp_page(&ctx).await.is_ok());
    world
        .put(
            &anna_ctx,
            &path,
            &meeting("m-1", &anna, &["mailto:other@example.net"]).build(),
        )
        .await
        .unwrap();
    assert_eq!(
        world.services.scheduling.rsvp_page(&ctx).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    world.run_outbox().await;
    let methods: Vec<String> = world
        .mails_to("guest@example.net")
        .await
        .iter()
        .map(|mail| calendar_of(&mail.mail).0)
        .collect();
    assert_eq!(methods, vec!["REQUEST", "CANCEL"], "the guest is told");

    // Deleting the event revokes the links of the remaining guests.
    let object = world.copy_of(&acme, &anna, "m-1").await.unwrap();
    let remaining = world.rsvp_tokens(&acme, object.id).await;
    let other = remaining
        .iter()
        .find(|row| row.attendee_address.as_str() == "mailto:other@example.net")
        .unwrap();
    let other_ctx = world.rsvp(&acme, other);
    assert!(world.services.scheduling.rsvp_page(&other_ctx).await.is_ok());
    world.delete(&anna_ctx, &path).await.unwrap();
    assert_eq!(
        world
            .services
            .scheduling
            .rsvp_page(&other_ctx)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
}

#[tokio::test]
async fn a_link_expires_seven_days_after_the_event_ended() {
    let Invited { world, acme, token, .. } = invited().await;
    let ctx = world.rsvp(&acme, &token);
    // The event is on 2027-03-10 from 09:00 to 10:00; the world starts on 2027-01-01.
    world.clock.advance(Duration::days(75));
    assert!(
        world.services.scheduling.rsvp_page(&ctx).await.is_ok(),
        "2027-03-17 09:00 is before the end of the grace period"
    );
    world.clock.advance(Duration::days(1));
    assert_eq!(
        world.services.scheduling.rsvp_page(&ctx).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
}

#[tokio::test]
async fn external_policy_decides_whether_a_guest_is_mailed() {
    for (policy, listed, mailed) in [
        (ExternalPolicy::Allow, vec![], true),
        (ExternalPolicy::Deny, vec![], false),
        (ExternalPolicy::Allowlist, vec!["example.net".to_owned()], true),
        (ExternalPolicy::Allowlist, vec!["example.org".to_owned()], false),
    ] {
        let world = World::new();
        let acme = world
            .org_with("acme", |settings| {
                settings.scheduling.external = policy;
                settings.scheduling.external_allowlist = listed.clone();
            })
            .await;
        let anna = world.user(&acme, "anna").await;
        let ctx = world.dav(&acme, &anna);
        let path = world.object(&acme, &anna, "m-1.ics");
        let outcome = world
            .put(&ctx, &path, &meeting("m-1", &anna, &[GUEST]).build())
            .await
            .unwrap();
        let expected = if mailed {
            ScheduleStatus::ImipSent
        } else {
            ScheduleStatus::Failed
        };
        assert_eq!(
            outcome.schedule.recipients.first().map(|r| r.status),
            Some(expected),
            "{policy:?} {listed:?}"
        );
        world.run_outbox().await;
        assert_eq!(world.mails().await.len(), usize::from(mailed), "{policy:?} {listed:?}");
        let stored = world.text(&ctx, &path).await;
        let code = if mailed { "1.1" } else { "5.1" };
        assert_eq!(status_in(&stored, GUEST).as_deref(), Some(code), "{stored}");
    }
}

#[tokio::test]
async fn a_principal_of_another_tenant_is_external_and_a_group_address_is_unknown() {
    let world = World::new();
    let acme = world.org("acme").await;
    let globex = world.org("globex").await;
    let anna = world.user(&acme, "anna").await;
    let dana = world.user(&globex, "dana").await;
    let team = world.group(&acme, "team", &[&anna]).await;
    let ctx = world.dav(&acme, &anna);
    let team_address = format!("/dav/principals/acme/{}/", team.name);

    let outcome = world
        .put(
            &ctx,
            &world.object(&acme, &anna, "m-1.ics"),
            &meeting("m-1", &anna, &[&dana.mailto(), &team_address]).build(),
        )
        .await
        .unwrap();

    let status_of = |who: &str| {
        outcome
            .schedule
            .recipients
            .iter()
            .find(|recipient| recipient.address.as_str().contains(who))
            .map(|recipient| recipient.status)
    };
    assert_eq!(
        status_of("dana"),
        Some(ScheduleStatus::ImipSent),
        "another tenant is mailed"
    );
    assert_eq!(
        status_of("team"),
        Some(ScheduleStatus::UnknownAddress),
        "groups are not expanded in 1.0"
    );
    assert_eq!(
        world.inbox(&globex, &dana).await.len(),
        0,
        "nothing crosses the tenant boundary"
    );
    assert!(world.copy_of(&globex, &dana, "m-1").await.is_none());
    world.run_outbox().await;
    assert_eq!(world.mails_to("dana@globex.example").await.len(), 1);
}

#[tokio::test]
async fn an_update_and_a_cancellation_are_mailed_with_the_same_link() {
    let Invited {
        world,
        acme,
        anna,
        token,
    } = invited().await;
    let ctx = world.dav(&acme, &anna);
    let path = world.object(&acme, &anna, "m-1.ics");
    // A new place is a significant change that does not move the end of the event: the invitation is sent again.
    let relocated = meeting("m-1", &anna, &[GUEST]).location("Room 2").build();
    world.put(&ctx, &path, &relocated).await.unwrap();
    world.run_outbox().await;
    // The update carries the link of the invitation: one token, not two.
    assert_eq!(world.rsvp_tokens(&acme, token.object_id).await.len(), 1);
    world.delete(&ctx, &path).await.unwrap();
    world.run_outbox().await;

    let mails = world.mails_to("guest@example.net").await;
    let methods: Vec<(String, Option<String>)> = mails
        .iter()
        .map(|mail| {
            let (method, ics) = calendar_of(&mail.mail);
            (method, property_in(&ics, "SEQUENCE"))
        })
        .collect();
    assert_eq!(
        methods,
        vec![
            ("REQUEST".to_owned(), None),
            ("REQUEST".to_owned(), Some("1".to_owned())),
            ("CANCEL".to_owned(), Some("1".to_owned()))
        ]
    );
    let link = |text: &str| {
        let (_, rest) = text.split_once("/rsvp/dvh_rsvp_").expect("the mail has a link");
        rest.split(char::is_whitespace).next().unwrap().to_owned()
    };
    assert_eq!(
        link(&mails[0].mail.text),
        link(&mails[1].mail.text),
        "the update has the link of the invitation"
    );
    assert!(!mails[2].mail.text.contains("/rsvp/"), "a cancellation has no link");
}

#[tokio::test]
async fn a_later_end_needs_a_link_that_lasts_as_long_and_the_old_one_keeps_working() {
    let Invited {
        world,
        acme,
        anna,
        token,
    } = invited().await;
    let ctx = world.dav(&acme, &anna);
    let later = meeting("m-1", &anna, &[GUEST])
        .starts(davhaven_testkit::davhaven_fixtures::event::When::utc(2027, 3, 20, 9, 0))
        .ends(davhaven_testkit::davhaven_fixtures::event::When::utc(
            2027, 3, 20, 10, 0,
        ))
        .build();
    world
        .put(&ctx, &world.object(&acme, &anna, "m-1.ics"), &later)
        .await
        .unwrap();
    world.run_outbox().await;
    // The first link would expire before the event is over: a second one is minted, and the first keeps working
    // until its own expiry (ADR 0007), so the mail the guest already has is not dead.
    let tokens = world.rsvp_tokens(&acme, token.object_id).await;
    assert_eq!(tokens.len(), 2);
    assert!(tokens.iter().all(|row| row.revoked_at.is_none()));
    assert!(
        world
            .services
            .scheduling
            .rsvp_page(&world.rsvp(&acme, &token))
            .await
            .is_ok()
    );
    let newest = tokens.iter().max_by_key(|row| row.expires_at).unwrap();
    assert!(newest.expires_at > token.expires_at);
}

#[tokio::test]
async fn an_internal_attendee_who_answers_an_external_organizer_sends_an_imip_reply() {
    // The organizer is outside the tenant: Ben's invitation comes in over the inbound endpoint (enabled for requests),
    // and his answer in a calendar client goes out as a mail.
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
    let response = world
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
    assert_eq!(
        response.outcome,
        davhaven_testkit::davhaven_wire::InboundOutcome::Applied
    );
    let copy = world
        .copy_of(&acme, &ben, "ext-1")
        .await
        .expect("the invitation became a copy in Ben's calendar");

    let accepted = super::support::answered(&copy.data, "mailto:ben@acme.example", PartStat::Accepted);
    world
        .put(
            &world.dav(&acme, &ben),
            &world.object(&acme, &ben, copy.uri.as_str()),
            &accepted,
        )
        .await
        .unwrap();
    world.run_outbox().await;

    let mails = world.mails_to("olga@example.net").await;
    assert_eq!(mails.len(), 1, "{:?}", world.mail_jobs(&acme).await);
    let (method, ics) = calendar_of(&mails[0].mail);
    assert_eq!(method, "REPLY");
    assert_eq!(
        partstat_in(&ics, "mailto:ben@acme.example"),
        Some(PartStat::Accepted),
        "{ics}"
    );
}
