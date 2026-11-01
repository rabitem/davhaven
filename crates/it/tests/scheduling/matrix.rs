//! The scheduling matrix (PLAN 3.3): organizer surface x attendee x change x reply channel x answer.
//!
//! The cases are those of `davhaven_testkit::scheduling::SchedulingCase::matrix()`: the full product of the
//! surface the organizer writes through (a CalDAV client, the management API, an MCP tool), the kind of attendee
//! (a colleague, somebody of another tenant, a group address, a room, a guest) and the change, and for each of them
//! one combination of reply channel and answer chosen so that every pair of values of any two dimensions occurs.
//!
//! A case builds a fresh world and does what a person would do:
//!
//! 1. the organizer creates the event with the attendee (or, for changes that need an earlier state, creates what
//!    the change is applied to) and the outbox is delivered;
//! 2. the organizer makes the change through the surface of the case;
//! 3. the attendee answers through the channel of the case, if the channel offers them a way to;
//! 4. everything that can be seen is compared with `table::expected`: the messages in the attendee's inbox, the
//!    copies in their calendars, the mails they got, the delivery state and the answer in the organizer's copy and
//!    the scheduling events.
//!
//! The driver never looks at what the application decided: the attempts of the attendee follow from what exists (a
//! copy to edit, a link to open, a mailbox to write from), and the expectation comes from the table alone. All cases
//! of a surface run in one test, so a regression shows every cell it breaks.

use std::fmt::Debug;

use davhaven_testkit::davhaven_app::error::AppError;
use davhaven_testkit::davhaven_app::services::{
    CsrfToken, DeleteEventOptions, MoveRequest, ObjectSelector, RsvpAnswer, WritePrecondition,
};
use davhaven_testkit::davhaven_domain::{
    CalendarKind, CuType, EventStatus, ExternalKey, PartStat, RequestContext, RsvpToken, Scope,
};
use davhaven_testkit::davhaven_fixtures::event::{Attendee, EventBuilder, Organizer, When};
use davhaven_testkit::scheduling::{AttendeeKind, Change, OrganizerSurface, ReplyChannel, SchedulingCase};
use serde_json::{Value, json};

use super::support::{
    Org, Person, World, answered, calendar_of, csrf_of, gateway_mail, partstat_in, property_in, reply_ical, status_in,
    write,
};
use super::table::{Expected, expected, partstat_of};

/// The UID of the event of every case.
const UID: &str = "m-1";

/// The messages of the scheduling events a case looks at; the others (`calendar.objects_changed`, ...) are not
/// scheduling.
const SCHEDULING_EVENTS: [&str; 3] = [
    "scheduling.reply_received",
    "scheduling.reply_rejected",
    "rsvp.answered",
];

/// What the event looks like at one point of a case.
#[derive(Debug, Clone, Default)]
struct Spec {
    location: Option<&'static str>,
    description: Option<&'static str>,
    recurring: bool,
    exdate: bool,
    cancelled: bool,
    attendees: Vec<String>,
}

/// The attendee under test: how events name them, where their mail goes and where they live.
struct Subject {
    /// The address as `ATTENDEE` lines write it.
    address: String,
    /// The mailbox of the attendee, when they have one (everybody but a group).
    mailbox: Option<&'static str>,
    /// The tenant and the principal of the attendee, when there is one.
    person: Option<(Org, Person)>,
}

/// The world of one case.
struct Scene {
    world: World,
    acme: Org,
    anna: Person,
    cara: Person,
    surface: OrganizerSurface,
    subject: Subject,
}

impl Scene {
    async fn new(case: &SchedulingCase) -> Self {
        let world = World::with_inbound();
        let acme = world.org("acme").await;
        let globex = world.org("globex").await;
        let anna = world.user(&acme, "anna").await;
        let cara = world.user(&acme, "cara").await;
        let ben = world.user(&acme, "ben").await;
        let room = world.resource(&acme, "room1").await;
        let dana = world.user(&globex, "dana").await;
        let team = world.group(&acme, "team", &[&anna]).await;
        world.calendar(&acme, &anna, "other", CalendarKind::User).await;
        let subject = match case.attendee {
            AttendeeKind::Internal => Subject {
                address: ben.mailto(),
                mailbox: Some("ben@acme.example"),
                person: Some((acme.clone(), ben)),
            },
            AttendeeKind::OtherTenant => Subject {
                address: dana.mailto(),
                mailbox: Some("dana@globex.example"),
                person: Some((globex, dana)),
            },
            AttendeeKind::GroupAddress => Subject {
                address: format!("/dav/principals/acme/{}/", team.name),
                mailbox: None,
                person: None,
            },
            AttendeeKind::Resource => Subject {
                address: room.mailto(),
                mailbox: Some("room1@acme.example"),
                person: Some((acme.clone(), room)),
            },
            AttendeeKind::External => Subject {
                address: "mailto:guest@example.net".to_owned(),
                mailbox: Some("guest@example.net"),
                person: None,
            },
        };
        Self {
            world,
            acme,
            anna,
            cara,
            surface: case.organizer,
            subject,
        }
    }

    /// The organizer in the surface of the case.
    fn ctx(&self) -> RequestContext {
        match self.surface {
            OrganizerSurface::Dav => self.world.dav(&self.acme, &self.anna),
            OrganizerSurface::Api => self
                .world
                .api(&self.acme, &self.anna, &[Scope::EventsWrite, Scope::EventsRead]),
            OrganizerSurface::Mcp => self.world.mcp(
                &self.acme,
                &self.anna,
                &[Scope::McpWrite, Scope::McpRead, Scope::McpScheduleExternal],
            ),
        }
    }

    /// The event as the iCalendar text a client writes.
    fn ics(&self, spec: &Spec) -> String {
        let mut event = EventBuilder::event(UID)
            .summary("Planning")
            .starts(When::utc(2027, 3, 10, 9, 0))
            .ends(When::utc(2027, 3, 10, 10, 0))
            .organizer(Organizer::new(&self.anna.mailto()));
        if let Some(location) = spec.location {
            event = event.location(location);
        }
        if let Some(description) = spec.description {
            event = event.description(description);
        }
        if spec.recurring {
            event = event.rrule("FREQ=DAILY;COUNT=3");
        }
        if spec.exdate {
            event = event.property("EXDATE", "20270311T090000Z");
        }
        if spec.cancelled {
            event = event.status(EventStatus::Cancelled);
        }
        for address in &spec.attendees {
            let attendee = Attendee::new(address);
            event = event.attendee(if address == "mailto:room1@acme.example" {
                attendee.cutype(CuType::Resource)
            } else {
                attendee
            });
        }
        event.build()
    }

    /// The event as the JSON the management API and MCP take.
    fn json(&self, spec: &Spec) -> Value {
        let mut event = json!({
            "uid": UID,
            "summary": "Planning",
            "start": {"date_time": "2027-03-10T09:00:00Z"},
            "end": {"date_time": "2027-03-10T10:00:00Z"},
            "organizer": {"address": self.anna.mailto()},
            "attendees": spec.attendees.iter().map(|address| json!({"address": address})).collect::<Vec<_>>(),
        });
        if let Some(fields) = event.as_object_mut() {
            if let Some(location) = spec.location {
                fields.insert("location".to_owned(), json!(location));
            }
            if let Some(description) = spec.description {
                fields.insert("description".to_owned(), json!(description));
            }
            if spec.recurring {
                let exdates = if spec.exdate {
                    vec![json!({"date_time": "2027-03-11T09:00:00Z"})]
                } else {
                    Vec::new()
                };
                fields.insert(
                    "recurrence".to_owned(),
                    json!({"rrule": "FREQ=DAILY;COUNT=3", "exdates": exdates}),
                );
            }
            if spec.cancelled {
                fields.insert("status".to_owned(), json!("cancelled"));
            }
        }
        event
    }

    /// Creates or replaces the event through the surface of the case.
    async fn write(&self, spec: &Spec) -> Result<(), AppError> {
        match self.surface {
            OrganizerSurface::Dav => self
                .world
                .put(
                    &self.ctx(),
                    &self.world.object(&self.acme, &self.anna, "m-1.ics"),
                    &self.ics(spec),
                )
                .await
                .map(|_| ()),
            OrganizerSurface::Api | OrganizerSurface::Mcp => self
                .world
                .services
                .objects
                .put_event(
                    &self.ctx(),
                    &self.world.collection(&self.acme, &self.anna, "personal"),
                    write(UID, &self.json(spec), true),
                )
                .await
                .map(|_| ()),
        }
    }

    /// Deletes the event through the surface of the case.
    async fn remove(&self) -> Result<(), AppError> {
        match self.surface {
            OrganizerSurface::Dav => self
                .world
                .delete(&self.ctx(), &self.world.object(&self.acme, &self.anna, "m-1.ics"))
                .await
                .map(|_| ()),
            OrganizerSurface::Api | OrganizerSurface::Mcp => {
                self.world
                    .services
                    .objects
                    .delete_event(
                        &self.ctx(),
                        &self.world.collection(&self.acme, &self.anna, "personal"),
                        &ObjectSelector::Key(ExternalKey::parse(UID).unwrap()),
                        DeleteEventOptions {
                            notify_attendees: true,
                            ..DeleteEventOptions::default()
                        },
                    )
                    .await
            }
        }
    }

    /// Moves the event to another calendar of the owner. Relocation exists in DAV only, so every surface does it
    /// there: the surface decides how an event is written, and a relocation is not a write of the event.
    async fn relocate(&self) -> Result<(), AppError> {
        let stored = self.world.copy_of(&self.acme, &self.anna, UID).await.unwrap();
        let from = self.world.path_of(&self.acme, &stored).await;
        let to = self
            .world
            .object_in(&self.acme, &self.anna, "other", stored.uri.as_str());
        self.world
            .services
            .objects
            .move_to(
                &self.world.dav(&self.acme, &self.anna),
                MoveRequest {
                    from,
                    to,
                    overwrite: false,
                    preconditions: WritePrecondition::none(),
                },
            )
            .await
            .map(|_| ())
    }
}

/// What a case did, as far as anybody can see it.
#[derive(Debug, PartialEq)]
struct Seen {
    inbox: Vec<String>,
    copies: usize,
    mails: Vec<String>,
    schedule_status: Option<String>,
    partstat: Option<PartStat>,
}

impl Scene {
    /// The messages, copies, mails and the organizer's copy as they are now.
    async fn look(&self) -> Seen {
        let world = &self.world;
        let (inbox, copies) = match &self.subject.person {
            Some((org, person)) => (
                world
                    .inbox(org, person)
                    .await
                    .iter()
                    .map(|item| property_in(&item.data, "METHOD").unwrap_or_default())
                    .collect(),
                world
                    .objects_of(org, person)
                    .await
                    .iter()
                    .filter(|object| object.uid.as_str() == UID)
                    .count(),
            ),
            None => (Vec::new(), 0),
        };
        let mails = match self.subject.mailbox {
            Some(mailbox) => world
                .mails_to(mailbox)
                .await
                .iter()
                .map(|mail| calendar_of(&mail.mail).0)
                .collect(),
            None => Vec::new(),
        };
        let organizer_copy = world.copy_of(&self.acme, &self.anna, UID).await;
        Seen {
            inbox,
            copies,
            mails,
            schedule_status: organizer_copy
                .as_ref()
                .and_then(|object| status_in(&object.data, &self.subject.address)),
            partstat: organizer_copy
                .as_ref()
                .and_then(|object| partstat_in(&object.data, &self.subject.address)),
        }
    }

    /// The scheduling events since `mark` events were there, sorted.
    async fn scheduling_events_since(&self, mark: usize) -> Vec<String> {
        let mut seen: Vec<String> = self
            .world
            .events(&self.acme)
            .await
            .iter()
            .skip(mark)
            .map(|envelope| envelope.event_type.as_str().to_owned())
            .filter(|name| SCHEDULING_EVENTS.contains(&name.as_str()))
            .collect();
        seen.sort_unstable();
        seen
    }

    /// The `SEQUENCE` of the last invitation mailed to the attendee: what a mail client puts into its answer.
    async fn sequence_of_last_invitation(&self) -> u32 {
        let Some(mailbox) = self.subject.mailbox else {
            return 0;
        };
        self.world
            .mails_to(mailbox)
            .await
            .iter()
            .rev()
            .map(|mail| calendar_of(&mail.mail))
            .find(|(method, _)| method == "REQUEST")
            .and_then(|(_, ics)| property_in(&ics, "SEQUENCE"))
            .and_then(|sequence| sequence.parse().ok())
            .unwrap_or(0)
    }

    /// The attendee answers through `channel`, as far as the channel offers them a way to. Whatever the application
    /// refuses is simply not applied; only an answer that should have worked and did not is a note.
    async fn answer(
        &self,
        channel: ReplyChannel,
        partstat: PartStat,
        tokens: &[RsvpToken],
        message_id: &str,
    ) -> Vec<String> {
        let mut notes = Vec::new();
        match channel {
            ReplyChannel::Dav => {
                // The attendee edits their own copy, if they have one.
                let Some((org, person)) = &self.subject.person else {
                    return notes;
                };
                let Some(copy) = self.world.copy_of(org, person, UID).await else {
                    return notes;
                };
                let path = self.world.path_of(org, &copy).await;
                let text = answered(&copy.data, &self.subject.address, partstat);
                if let Err(error) = self.world.put(&self.world.dav(org, person), &path, &text).await {
                    notes.push(format!("the answer in the calendar was refused: {error:?}"));
                }
            }
            ReplyChannel::Rsvp => {
                // The attendee opens the link of their invitation, if they got one, and answers on the page.
                let Some(token) = tokens
                    .iter()
                    .filter(|token| token.attendee_address.as_str() == self.subject.address)
                    .max_by_key(|token| token.created_at)
                else {
                    return notes;
                };
                let ctx = self.world.rsvp(&self.acme, token);
                let Ok(page) = self.world.services.scheduling.rsvp_page(&ctx).await else {
                    // A link that no longer works shows nothing to answer.
                    return notes;
                };
                let answer = RsvpAnswer {
                    partstat,
                    comment: None,
                };
                if let Err(error) = self
                    .world
                    .services
                    .scheduling
                    .rsvp_answer(&ctx, answer, CsrfToken::new(csrf_of(&page.html)))
                    .await
                {
                    notes.push(format!("the answer on the page was refused: {error:?}"));
                }
            }
            ReplyChannel::Inbound => {
                // The mail client of the attendee answers, and a gateway forwards the mail.
                let Some(mailbox) = self.subject.mailbox else {
                    return notes;
                };
                let sequence = self.sequence_of_last_invitation().await;
                let ical = reply_ical(
                    UID,
                    &self.anna.mailto(),
                    &self.subject.address,
                    partstat,
                    sequence,
                    None,
                );
                if let Err(error) = self
                    .world
                    .inbound(&self.acme, gateway_mail(mailbox, message_id, &ical))
                    .await
                {
                    notes.push(format!("the gateway was refused: {error:?}"));
                }
            }
        }
        notes
    }

    /// The links of the invitation `object`.
    async fn tokens_of(&self, object: Option<davhaven_testkit::davhaven_domain::StoredObject>) -> Vec<RsvpToken> {
        match object {
            Some(object) => self.world.rsvp_tokens(&self.acme, object.id).await,
            None => Vec::new(),
        }
    }
}

/// What the event is before the change and after it.
fn specs(case: SchedulingCase, scene: &Scene) -> (Option<Spec>, Spec) {
    let subject = scene.subject.address.clone();
    let cara = scene.cara.mailto();
    let base = Spec {
        attendees: vec![subject.clone()],
        ..Spec::default()
    };
    match case.change {
        Change::Create => (None, base),
        Change::Significant => (
            Some(base.clone()),
            Spec {
                location: Some("Room 2"),
                ..base
            },
        ),
        Change::Insignificant => (
            Some(base.clone()),
            Spec {
                description: Some("Bring the plan"),
                ..base
            },
        ),
        Change::AddAttendee => (
            Some(Spec {
                attendees: vec![cara.clone()],
                ..Spec::default()
            }),
            Spec {
                attendees: vec![cara, subject],
                ..Spec::default()
            },
        ),
        Change::RemoveAttendee => (
            Some(Spec {
                attendees: vec![subject, cara.clone()],
                ..Spec::default()
            }),
            Spec {
                attendees: vec![cara],
                ..Spec::default()
            },
        ),
        Change::CancelInstance => (
            Some(Spec {
                recurring: true,
                ..base.clone()
            }),
            Spec {
                recurring: true,
                exdate: true,
                ..base
            },
        ),
        Change::CancelSeries => (
            Some(base.clone()),
            Spec {
                cancelled: true,
                ..base
            },
        ),
        Change::Delete | Change::Move => (Some(base.clone()), base),
    }
}

fn compare<T: PartialEq + Debug>(diffs: &mut Vec<String>, what: &str, actual: &T, expected: &T) {
    if actual != expected {
        diffs.push(format!("{what}: expected {expected:?}, got {actual:?}"));
    }
}

/// Performs one case and returns what differs from the table.
async fn run_case(case: SchedulingCase, number: usize) -> Vec<String> {
    let scene = Scene::new(&case).await;
    let wanted: Expected = expected(case);
    let mut diffs = Vec::new();

    // 1. What the change is applied to.
    let (before, after) = specs(case, &scene);
    if let Some(before) = &before {
        if let Err(error) = scene.write(before).await {
            return vec![format!("the event could not be created: {error:?}")];
        }
        scene.world.run_outbox().await;
    }
    let tokens_before = scene
        .tokens_of(scene.world.copy_of(&scene.acme, &scene.anna, UID).await)
        .await;
    let mark = scene.world.events(&scene.acme).await.len();

    // 2. The change.
    let changed = match case.change {
        Change::Delete => scene.remove().await,
        Change::Move => scene.relocate().await,
        _ => scene.write(&after).await,
    };
    if let Err(error) = changed {
        return vec![format!("the change was refused: {error:?}")];
    }
    scene.world.run_outbox().await;
    let tokens_after = scene
        .tokens_of(scene.world.copy_of(&scene.acme, &scene.anna, UID).await)
        .await;

    let seen = scene.look().await;
    compare(
        &mut diffs,
        "messages in the inbox",
        &seen.inbox,
        &to_strings(&wanted.inbox),
    );
    compare(&mut diffs, "copies in the calendars", &seen.copies, &wanted.copies);
    compare(&mut diffs, "mails", &seen.mails, &to_strings(&wanted.mails));
    compare(
        &mut diffs,
        "SCHEDULE-STATUS in the organizer's copy",
        &seen.schedule_status,
        &wanted.schedule_status.map(str::to_owned),
    );
    compare(
        &mut diffs,
        "PARTSTAT in the organizer's copy before the answer",
        &seen.partstat,
        &wanted.partstat_before_reply,
    );

    // 3. The answer.
    let tokens: Vec<RsvpToken> = tokens_after.into_iter().chain(tokens_before).collect();
    let message_id = format!("<case-{number}@example.net>");
    diffs.extend(
        scene
            .answer(case.reply, partstat_of(case.answer), &tokens, &message_id)
            .await,
    );

    compare(
        &mut diffs,
        "PARTSTAT in the organizer's copy after the answer",
        &scene.look().await.partstat,
        &wanted.partstat_after_reply,
    );
    compare(
        &mut diffs,
        "scheduling events",
        &scene.scheduling_events_since(mark).await,
        &to_strings(&wanted.events),
    );
    diffs
}

fn to_strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|text| (*text).to_owned()).collect()
}

/// Runs every case of one surface and fails with all the cells that differ.
async fn run_surface(surface: OrganizerSurface) {
    let cases: Vec<(usize, SchedulingCase)> = SchedulingCase::matrix()
        .into_iter()
        .enumerate()
        .filter(|(_, case)| case.organizer == surface)
        .collect();
    assert_eq!(cases.len(), 45, "five kinds of attendee and nine changes");
    let mut failures: Vec<String> = Vec::new();
    for (number, case) in &cases {
        let diffs = run_case(*case, *number).await;
        if !diffs.is_empty() {
            failures.push(format!("  {case}\n      {}", diffs.join("\n      ")));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases of the {surface} surface differ from the decision table:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

#[tokio::test]
async fn the_organizer_writes_with_a_calendar_client() {
    run_surface(OrganizerSurface::Dav).await;
}

#[tokio::test]
async fn the_organizer_writes_through_the_management_api() {
    run_surface(OrganizerSurface::Api).await;
}

#[tokio::test]
async fn the_organizer_writes_through_an_mcp_tool() {
    run_surface(OrganizerSurface::Mcp).await;
}
