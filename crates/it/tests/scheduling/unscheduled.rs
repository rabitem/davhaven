//! What is not scheduled (PLAN 2.8, "Not scheduled") and what an attendee may change on their own copy.

use std::fmt::Write as _;

use davhaven_testkit::davhaven_domain::{CalendarKind, ErrorKind, PartStat, Precondition, Scope};

use super::support::{Org, Person, World, event, meeting, partstat_in, status_in, write};

/// A calendar object with an event and the given content lines (the organizer and the attendees, without line ends).
fn raw(component: &str, uid: &str, lines: &[&str]) -> String {
    let mut text = format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\nBEGIN:{component}\r\nUID:{uid}\r\nDTSTAMP:20270101T000000Z\r\n\
         DTSTART:20270310T090000Z\r\nSUMMARY:Planning\r\n"
    );
    if component == "VEVENT" {
        text.push_str("DTEND:20270310T100000Z\r\n");
    }
    for line in lines {
        text.push_str(line);
        text.push_str("\r\n");
    }
    let _ = write!(text, "END:{component}\r\nEND:VCALENDAR\r\n");
    text
}

async fn colleagues() -> (World, Org, Person, Person, Person) {
    let world = World::new();
    let acme = world.org("acme").await;
    let anna = world.user(&acme, "anna").await;
    let ben = world.user(&acme, "ben").await;
    let cara = world.user(&acme, "cara").await;
    (world, acme, anna, ben, cara)
}

#[tokio::test]
async fn attendees_that_a_client_schedules_are_left_alone() {
    let (world, acme, anna, ben, cara) = colleagues().await;
    let organizer = format!("ORGANIZER:{}", anna.mailto());
    let client = format!("ATTENDEE;SCHEDULE-AGENT=CLIENT;PARTSTAT=NEEDS-ACTION:{}", ben.mailto());
    let server = format!("ATTENDEE;PARTSTAT=NEEDS-ACTION:{}", cara.mailto());
    let ctx = world.dav(&acme, &anna);
    let path = world.object(&acme, &anna, "m-1.ics");

    let outcome = world
        .put(&ctx, &path, &raw("VEVENT", "m-1", &[&organizer, &client, &server]))
        .await
        .unwrap();

    assert_eq!(
        outcome.schedule.recipients.len(),
        1,
        "only the attendee the server schedules for"
    );
    assert_eq!(world.inbox(&acme, &ben).await.len(), 0);
    assert!(world.copy_of(&acme, &ben, "m-1").await.is_none());
    assert_eq!(world.inbox(&acme, &cara).await.len(), 1);
    let stored = world.text(&ctx, &path).await;
    assert_eq!(status_in(&stored, &cara.mailto()).as_deref(), Some("1.2"));
    assert_eq!(
        status_in(&stored, &ben.mailto()),
        None,
        "the client of Ben keeps the line as it was written"
    );
}

#[tokio::test]
async fn to_dos_are_never_scheduled() {
    let (world, acme, anna, ben, _cara) = colleagues().await;
    let outcome = world
        .put(
            &world.dav(&acme, &anna),
            &world.object(&acme, &anna, "t-1.ics"),
            &raw(
                "VTODO",
                "t-1",
                &[
                    &format!("ORGANIZER:{}", anna.mailto()),
                    &format!("ATTENDEE;PARTSTAT=NEEDS-ACTION:{}", ben.mailto()),
                ],
            ),
        )
        .await
        .unwrap();
    assert!(!outcome.schedule.is_scheduled());
    assert_eq!(world.inbox(&acme, &ben).await.len(), 0);
    assert_eq!(world.mail_jobs(&acme).await.len(), 0);
}

#[tokio::test]
async fn an_event_that_nobody_here_is_part_of_is_stored_as_it_is() {
    // An imported event of somebody else's meeting: neither the organizer nor an attendee is in this tenant.
    let (world, acme, anna, _ben, _cara) = colleagues().await;
    let ctx = world.dav(&acme, &anna);
    let outcome = world
        .put(
            &ctx,
            &world.object(&acme, &anna, "foreign.ics"),
            &raw(
                "VEVENT",
                "foreign",
                &[
                    "ORGANIZER:mailto:olga@example.net",
                    "ATTENDEE;PARTSTAT=ACCEPTED:mailto:guest@example.net",
                ],
            ),
        )
        .await
        .unwrap();
    assert!(!outcome.schedule.is_scheduled());
    assert_eq!(
        world.mail_jobs(&acme).await.len(),
        0,
        "nothing is mailed on behalf of somebody else"
    );
    assert_eq!(world.objects_of(&acme, &anna).await.len(), 1);
}

#[tokio::test]
async fn an_event_without_attendees_has_nothing_to_schedule_until_somebody_is_invited() {
    let (world, acme, anna, ben, _cara) = colleagues().await;
    let ctx = world.dav(&acme, &anna);
    let path = world.object(&acme, &anna, "m-1.ics");
    let organizer = format!("ORGANIZER:{}", anna.mailto());

    let outcome = world
        .put(&ctx, &path, &raw("VEVENT", "m-1", &[&organizer]))
        .await
        .unwrap();
    assert!(!outcome.schedule.is_scheduled());
    assert!(world.copy_of(&acme, &anna, "m-1").await.is_none());

    let invited = raw("VEVENT", "m-1", &[&organizer, &format!("ATTENDEE:{}", ben.mailto())]);
    let outcome = world.put(&ctx, &path, &invited).await.unwrap();
    assert_eq!(outcome.schedule.recipients.len(), 1);
    assert_eq!(
        world.inbox(&acme, &ben).await.len(),
        1,
        "the first invitation of an event that existed already"
    );
}

#[tokio::test]
async fn a_managed_calendar_is_not_scheduled_even_when_the_caller_asks() {
    let (world, acme, anna, ben, _cara) = colleagues().await;
    world.calendar(&acme, &anna, "managed", CalendarKind::Managed).await;
    let ctx = world.tenant_token(&acme, &[Scope::EventsWrite, Scope::EventsRead]);
    let outcome = world
        .services
        .objects
        .put_event(
            &ctx,
            &world.collection(&acme, &anna, "managed"),
            write("shift", &event("Shift", &anna, &[&ben.mailto()]), true),
        )
        .await
        .unwrap();
    assert!(!outcome.schedule.is_scheduled());
    assert_eq!(world.inbox(&acme, &ben).await.len(), 0);
    assert_eq!(world.mail_jobs(&acme).await.len(), 0);
}

#[tokio::test]
async fn an_attendee_may_change_alarms_and_transparency_without_telling_anybody() {
    let (world, acme, anna, ben, _cara) = colleagues().await;
    world
        .put(
            &world.dav(&acme, &anna),
            &world.object(&acme, &anna, "m-1.ics"),
            &meeting("m-1", &anna, &[&ben.mailto()]).build(),
        )
        .await
        .unwrap();
    let copy = world.copy_of(&acme, &ben, "m-1").await.unwrap();
    let path = world.object(&acme, &ben, copy.uri.as_str());
    let reminded = copy.data.replace(
        "END:VEVENT",
        "TRANSP:TRANSPARENT\r\nBEGIN:VALARM\r\nACTION:DISPLAY\r\nDESCRIPTION:Reminder\r\nTRIGGER:-PT15M\r\nEND:VALARM\r\nEND:VEVENT",
    );

    world.put(&world.dav(&acme, &ben), &path, &reminded).await.unwrap();

    let stored = world.copy_of(&acme, &ben, "m-1").await.unwrap();
    assert!(
        stored.data.contains("VALARM") && stored.data.contains("TRANSP:TRANSPARENT"),
        "{}",
        stored.data
    );
    assert_eq!(world.inbox(&acme, &anna).await.len(), 0, "no answer, nothing to tell");
    let organizer_copy = world
        .text(&world.dav(&acme, &anna), &world.object(&acme, &anna, "m-1.ics"))
        .await;
    assert!(
        !organizer_copy.contains("VALARM"),
        "the alarm is the attendee's own: {organizer_copy}"
    );
    assert_eq!(partstat_in(&organizer_copy, &ben.mailto()), Some(PartStat::NeedsAction));
}

#[tokio::test]
async fn an_attendee_may_neither_answer_for_somebody_else_nor_leave_the_event_by_editing_it() {
    let (world, acme, anna, ben, cara) = colleagues().await;
    world
        .put(
            &world.dav(&acme, &anna),
            &world.object(&acme, &anna, "m-1.ics"),
            &meeting("m-1", &anna, &[&ben.mailto(), &cara.mailto()]).build(),
        )
        .await
        .unwrap();
    let copy = world.copy_of(&acme, &ben, "m-1").await.unwrap();
    let path = world.object(&acme, &ben, copy.uri.as_str());
    let ctx = world.dav(&acme, &ben);

    // Ben's copy shows only his own line. He cannot add Cara with an answer of her own to it.
    let with_cara = copy.data.replace(
        "END:VEVENT",
        &format!("ATTENDEE;PARTSTAT=ACCEPTED:{}\r\nEND:VEVENT", cara.mailto()),
    );
    let error = world.put(&ctx, &path, &with_cara).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    assert_eq!(
        error.precondition(),
        Some(&Precondition::AllowedAttendeeSchedulingObjectChange)
    );

    // Removing the own line is not how an attendee leaves: deleting the copy declines (and says so).
    let own_line = format!(":{}", ben.mailto());
    let without_self: String = copy
        .data
        .replace("\r\n ", "")
        .split_inclusive("\r\n")
        .filter(|line| !(line.starts_with("ATTENDEE") && line.contains(&own_line)))
        .collect();
    let error = world.put(&ctx, &path, &without_self).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    assert_eq!(
        error.precondition(),
        Some(&Precondition::AllowedAttendeeSchedulingObjectChange)
    );

    assert_eq!(
        world.copy_of(&acme, &ben, "m-1").await.unwrap().data,
        copy.data,
        "nothing was stored"
    );
    assert_eq!(world.inbox(&acme, &anna).await.len(), 0);
}
