//! The scheduling matrix over HTTP (PLAN 3.3).
//!
//! A case builds a fresh application and does what people do, through the surfaces they use:
//!
//! 1. the organizer (Olivia of the fixture world) creates the event with the attendee through the surface of the case:
//!    a CalDAV client `PUT`s the object, the management API writes it as JSON with `notify_attendees`, an MCP tool
//!    creates it; the outbox is delivered;
//! 2. the organizer makes the change through the same surface;
//! 3. the attendee answers through the channel of the case if it offers them a way to: they change `PARTSTAT` of their
//!    copy in a CalDAV client, they open the RSVP link of the invitation mail and press a button, or a mail gateway
//!    posts their reply to the inbound endpoint;
//! 4. everything that can be seen is compared with the decision table ([`super::table::expected`]): the messages in the
//!    attendee's scheduling inbox, their copies, the mails they got and their `METHOD`, the delivery state and the answer
//!    in the organizer's copy (read with a `GET` as the organizer) and the scheduling events.
//!
//! The driver never looks at what the application decided: the attempts of the attendee follow from what exists (a copy
//! to edit, a link in a mail, a mailbox to write from), and the expectation comes from the table alone. The RSVP link is
//! taken out of the mail the application sent, as a guest would.
//!
//! The application is the in-process one ([`TestApp`]), because the matrix looks at its mail transport, its event sink
//! and its store; the actions all go through the HTTP surfaces.

use davhaven_domain::{CuType, EventStatus, InboxItem, PartStat, PrincipalId, Scope, TenantId};
use davhaven_fixtures::event::{Attendee, EventBuilder, Organizer, When};
use davhaven_fixtures::{ActorRole, names};
use davhaven_ports::{InboxScope, PageReq, TxMode};
use serde_json::{Value, json};

use super::table::{Expected, expected, partstat_of};
use super::text::{answered, csrf_of, partstat_in, property_in, reply_ical, rsvp_tokens_in, status_in};
use super::{AttendeeKind, Change, OrganizerSurface, ReplyChannel, SchedulingCase};
use crate::app::{PUBLIC_BASE_URL, StoreKind, TestApp};
use crate::busy;
use crate::handles::{Actor, mcp_message};
use crate::permissions::{RunOptions, Sampling};
use crate::transport::TestResponse;

/// The UID of the event of every case.
const UID: &str = "m-1";

/// The scheduling events a case looks at; the others (`calendar.objects_changed`, ...) are not scheduling.
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
    mailbox: Option<String>,
    /// The tenant slug and the name of the principal of the attendee, when there is one.
    person: Option<(String, String)>,
}

/// The world of one case.
struct Scene {
    app: TestApp,
    surface: OrganizerSurface,
    subject: Subject,
}

fn problem(what: &str, response: &TestResponse) -> String {
    format!(
        "{what}: status {} ({})",
        response.status.as_u16(),
        response.excerpt(200)
    )
}

impl Scene {
    async fn new(case: &SchedulingCase, store: StoreKind) -> Result<Self, String> {
        // A world that cannot be made because the cluster is busy is made again before the case is called failed.
        let app = TestApp::build_with_retries(|| {
            TestApp::builder()
                .store(store)
                .configure(|config| config.scheduling.inbound_itip.enabled = true)
        })
        .await
        .map_err(|error| error.to_string())?;
        let at = |name: &str| format!("mailto:{name}@acme.example");
        let subject = match case.attendee {
            AttendeeKind::Internal => Subject {
                address: at(names::OTHER_USER),
                mailbox: Some("otto@acme.example".to_owned()),
                person: Some((names::TENANT.to_owned(), names::OTHER_USER.to_owned())),
            },
            AttendeeKind::OtherTenant => Subject {
                address: format!("mailto:{}@globex.example", names::OTHER_TENANT_USER),
                mailbox: Some("gina@globex.example".to_owned()),
                person: Some((names::OTHER_TENANT.to_owned(), names::OTHER_TENANT_USER.to_owned())),
            },
            AttendeeKind::GroupAddress => Subject {
                address: format!("/dav/principals/{}/{}/", names::TENANT, names::TEAM),
                mailbox: None,
                person: None,
            },
            AttendeeKind::Resource => Subject {
                address: at(names::RESOURCE),
                mailbox: Some("room1@acme.example".to_owned()),
                person: Some((names::TENANT.to_owned(), names::RESOURCE.to_owned())),
            },
            AttendeeKind::External => Subject {
                address: "mailto:guest@example.net".to_owned(),
                mailbox: Some("guest@example.net".to_owned()),
                person: None,
            },
        };
        let scene = Self {
            app,
            surface: case.organizer,
            subject,
        };
        scene.give_the_room_a_calendar().await?;
        Ok(scene)
    }

    /// The room answers by free-busy, so it needs a calendar to look at.
    async fn give_the_room_a_calendar(&self) -> Result<(), String> {
        let admin = self
            .app
            .api(&self.app.token(ActorRole::TenantToken).map_err(|e| e.to_string())?);
        let response = admin
            .put_json(
                &format!(
                    "/api/v1/tenants/{}/principals/{}/calendars/room",
                    names::TENANT,
                    names::RESOURCE
                ),
                &json!({"display_name": "Room calendar"}),
            )
            .map_err(|e| e.to_string())?
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if response.status.is_success() {
            Ok(())
        } else {
            Err(problem("the room's calendar cannot be made", &response))
        }
    }

    fn organizer_dav(&self) -> Result<Actor, String> {
        self.app.actor(ActorRole::Owner).map_err(|e| e.to_string())
    }

    fn organizer_api(&self) -> Result<Actor, String> {
        self.app
            .token(ActorRole::Owner)
            .map(|token| Actor::bearer(token.secret()))
            .map_err(|e| e.to_string())
    }

    fn organizer_address(&self) -> String {
        format!("mailto:{}@{}", names::OWNER, self.app.world().names.login_domain)
    }

    fn collection(slug: &str) -> String {
        format!("/dav/calendars/{}/{}/{slug}/", names::TENANT, names::OWNER)
    }

    fn by_key() -> String {
        format!(
            "/api/v1/tenants/{}/principals/{}/calendars/personal/objects/by-key/{UID}?notify_attendees=true",
            names::TENANT,
            names::OWNER
        )
    }

    /// The event as the iCalendar text a client writes.
    fn ics(&self, spec: &Spec) -> String {
        let mut event = EventBuilder::event(UID)
            .summary("Planning")
            .starts(When::utc(2027, 3, 10, 9, 0))
            .ends(When::utc(2027, 3, 10, 10, 0))
            .organizer(Organizer::new(&self.organizer_address()));
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
            event = event.attendee(if address.contains(names::RESOURCE) {
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
            "organizer": {"address": self.organizer_address()},
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
    async fn write(&self, spec: &Spec) -> Result<(), String> {
        let response = match self.surface {
            OrganizerSurface::Dav => {
                let target = format!("{}{UID}.ics", Self::collection("personal"));
                self.app
                    .dav(&self.organizer_dav()?)
                    .put(&target, &self.ics(spec))
                    .send()
                    .await
            }
            OrganizerSurface::Api => {
                let request = self
                    .app
                    .api_as(&self.organizer_api()?)
                    .put_json(&Self::by_key(), &self.json(spec))
                    .map_err(|e| e.to_string())?;
                request.send().await
            }
            OrganizerSurface::Mcp => return self.mcp_write(spec).await,
        }
        .map_err(|e| e.to_string())?;
        if response.status.is_success() {
            Ok(())
        } else {
            Err(problem("the write was refused", &response))
        }
    }

    /// Writes through the MCP tools: `create_event`, or `update_event` when the event exists.
    async fn mcp_write(&self, spec: &Spec) -> Result<(), String> {
        let token = self.organizer_api()?;
        let (calendar, existing) = self.mcp_ids().await?;
        let mcp = self.app.mcp_as(&token);
        let event = self.json(spec);
        let call = match existing {
            None => mcp.call_tool(
                "create_event",
                &json!({
                    "calendar_id": calendar,
                    "client_request_id": UID,
                    "event": event,
                    "notify_attendees": true
                }),
            ),
            Some(id) => mcp.call_tool(
                "update_event",
                &json!({
                    "calendar_id": calendar,
                    "event_id": id,
                    "scope": "all",
                    "changes": event,
                    "notify_attendees": true
                }),
            ),
        }
        .map_err(|e| e.to_string())?;
        let response = call.send().await.map_err(|e| e.to_string())?;
        let message = mcp_message(&response).map_err(|e| e.to_string())?;
        if message.pointer("/result/isError").and_then(Value::as_bool) == Some(true) || message.get("error").is_some() {
            return Err(format!("the tool call failed: {message}"));
        }
        Ok(())
    }

    /// The id of the organizer's personal calendar and, when the event exists, of its object.
    async fn mcp_ids(&self) -> Result<(String, Option<String>), String> {
        let calendar = self
            .app
            .world()
            .calendar(davhaven_fixtures::CalendarRole::Personal)
            .map_err(|e| e.to_string())?
            .key
            .clone();
        let calendar_id = *self
            .app
            .index()
            .calendars
            .get(&calendar)
            .ok_or("the calendar is not seeded")?;
        let tenant = self.app.tenant_id(names::TENANT).ok_or("the tenant is not seeded")?;
        let mut tx = self
            .app
            .deps()
            .database
            .begin(tenant, TxMode::ReadOnly)
            .await
            .map_err(|e| e.to_string())?;
        let uri = davhaven_domain::ObjectUri::parse(&format!("{UID}.ics")).map_err(|e| e.to_string())?;
        let object = tx
            .objects()
            .get(calendar_id, &uri)
            .await
            .ok()
            .map(|object| object.id.to_string());
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok((calendar_id.to_string(), object))
    }

    /// Deletes the event through the surface of the case.
    async fn remove(&self) -> Result<(), String> {
        let response = match self.surface {
            OrganizerSurface::Dav => {
                let target = format!("{}{UID}.ics", Self::collection("personal"));
                self.app.dav(&self.organizer_dav()?).delete(&target).send().await
            }
            OrganizerSurface::Api => {
                self.app
                    .api_as(&self.organizer_api()?)
                    .delete(&Self::by_key(), None)
                    .send()
                    .await
            }
            OrganizerSurface::Mcp => {
                let (calendar, existing) = self.mcp_ids().await?;
                let id = existing.ok_or("the event to delete does not exist")?;
                let call = self
                    .app
                    .mcp_as(&self.organizer_api()?)
                    .call_tool(
                        "delete_event",
                        &json!({"calendar_id": calendar, "event_id": id, "scope": "all", "notify_attendees": true}),
                    )
                    .map_err(|e| e.to_string())?;
                call.send().await
            }
        }
        .map_err(|e| e.to_string())?;
        if response.status.is_success() {
            Ok(())
        } else {
            Err(problem("the deletion was refused", &response))
        }
    }

    /// Moves the event to another calendar of the owner. Relocation exists in DAV only, so every surface does it there:
    /// the surface decides how an event is written, and a relocation is not a write of the event.
    async fn relocate(&self) -> Result<(), String> {
        let from = format!("{}{UID}.ics", Self::collection("personal"));
        let to = format!("{}{UID}.ics", Self::collection("projects"));
        let response = self
            .app
            .dav(&self.organizer_dav()?)
            .move_to(&from, &to)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if response.status.is_success() {
            Ok(())
        } else {
            Err(problem("the relocation was refused", &response))
        }
    }

    // -------------------------------------------------------------------------------------------------------------
    // Looking
    // -------------------------------------------------------------------------------------------------------------

    fn ids_of_subject(&self) -> Option<(TenantId, PrincipalId)> {
        let (tenant, name) = self.subject.person.as_ref()?;
        Some((self.app.tenant_id(tenant)?, self.app.index().principal(tenant, name)?))
    }

    /// The messages in the scheduling inbox and the copies of the event in the calendars of the attendee.
    async fn inbox_and_copies(&self) -> Result<(Vec<String>, usize), String> {
        let Some((tenant, principal)) = self.ids_of_subject() else {
            return Ok((Vec::new(), 0));
        };
        let mut tx = self
            .app
            .deps()
            .database
            .begin(tenant, TxMode::ReadOnly)
            .await
            .map_err(|e| e.to_string())?;
        let items: Vec<InboxItem> = tx
            .inbox()
            .list(principal, InboxScope::Delivered)
            .await
            .map_err(|e| e.to_string())?;
        let inbox = items
            .iter()
            .map(|item| property_in(&item.data, "METHOD").unwrap_or_default())
            .collect();
        let mut copies = 0;
        for calendar in tx.calendars().list_owned(principal).await.map_err(|e| e.to_string())? {
            let mut page = PageReq::first(1000);
            loop {
                let batch = tx.objects().list(calendar.id, page).await.map_err(|e| e.to_string())?;
                copies += batch.items.iter().filter(|object| object.uid.as_str() == UID).count();
                match batch.next {
                    Some(after) => page = page.after(after),
                    None => break,
                }
            }
        }
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok((inbox, copies))
    }

    /// The organizer's copy as the organizer reads it, wherever the event is.
    async fn organizer_copy(&self) -> Result<Option<String>, String> {
        let organizer = self.organizer_dav()?;
        for slug in ["personal", "projects"] {
            let target = format!("{}{UID}.ics", Self::collection(slug));
            let response = self
                .app
                .dav(&organizer)
                .get(&target)
                .send()
                .await
                .map_err(|e| e.to_string())?;
            if response.status.is_success() {
                return Ok(Some(response.text()));
            }
        }
        Ok(None)
    }

    /// The `METHOD` of every mail to the attendee, in order of sending.
    async fn mail_methods(&self) -> Vec<String> {
        match &self.subject.mailbox {
            Some(mailbox) => self
                .app
                .mails()
                .to(mailbox)
                .await
                .iter()
                .filter_map(|captured| captured.mail.calendar.as_ref())
                .map(|part| part.method.as_ical().to_owned())
                .collect(),
            None => Vec::new(),
        }
    }

    async fn look(&self) -> Result<Seen, String> {
        let (inbox, copies) = self.inbox_and_copies().await?;
        let copy = self.organizer_copy().await?;
        Ok(Seen {
            inbox,
            copies,
            mails: self.mail_methods().await,
            schedule_status: copy.as_ref().and_then(|text| status_in(text, &self.subject.address)),
            partstat: copy.as_ref().and_then(|text| partstat_in(text, &self.subject.address)),
        })
    }

    /// The scheduling events since `mark` events were there, sorted.
    async fn scheduling_events_since(&self, mark: usize) -> Vec<String> {
        let mut seen: Vec<String> = self
            .app
            .events()
            .unique()
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
        let Some(mailbox) = &self.subject.mailbox else {
            return 0;
        };
        self.app
            .mails()
            .to(mailbox)
            .await
            .iter()
            .rev()
            .filter_map(|captured| captured.mail.calendar.as_ref())
            .find(|part| part.method.as_ical() == "REQUEST")
            .and_then(|part| property_in(&part.ics, "SEQUENCE"))
            .and_then(|sequence| sequence.parse().ok())
            .unwrap_or(0)
    }

    // -------------------------------------------------------------------------------------------------------------
    // Answering
    // -------------------------------------------------------------------------------------------------------------

    /// The DAV credentials of the attendee: their app password, or for the room one the harness issues.
    async fn attendee_dav(&self) -> Result<Option<(String, Actor)>, String> {
        let Some((tenant, name)) = &self.subject.person else {
            return Ok(None);
        };
        let role = match name.as_str() {
            names::OTHER_USER => Some(ActorRole::OtherUser),
            names::OTHER_TENANT_USER => Some(ActorRole::OtherTenantUser),
            _ => None,
        };
        if let Some(role) = role {
            return Ok(self.app.actor(role).ok().map(|actor| (name.clone(), actor)));
        }
        // The room has no login in the fixture world: a person who looks after it gets an app password.
        let admin = self
            .app
            .api(&self.app.token(ActorRole::TenantToken).map_err(|e| e.to_string())?);
        let response = admin
            .post_json(
                &format!("/api/v1/tenants/{tenant}/principals/{name}/app-passwords"),
                &json!({"label": "room"}),
            )
            .map_err(|e| e.to_string())?
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !response.status.is_success() {
            return Err(problem("an app password for the room cannot be made", &response));
        }
        let body: Value = response.json().map_err(|e| e.to_string())?;
        let password = body
            .get("password")
            .and_then(Value::as_str)
            .ok_or("the app password has no secret")?;
        let login = format!("{name}@{}", self.app.world().names.login_domain);
        Ok(Some((name.clone(), Actor::basic(login, password))))
    }

    /// The attendee answers through `channel`, as far as the channel offers them a way to. Whatever the application
    /// refuses is simply not applied; only an answer that should have worked and did not is a note.
    async fn answer(&self, channel: ReplyChannel, partstat: PartStat, message_id: &str) -> Vec<String> {
        let mut notes = Vec::new();
        match channel {
            ReplyChannel::Dav => {
                let Some((tenant, _)) = self.subject.person.as_ref() else {
                    return notes;
                };
                let Ok(Some((name, actor))) = self.attendee_dav().await else {
                    return notes;
                };
                // A person keeps invitations in the personal calendar, the room in the calendar it was given.
                let slug = if name == names::RESOURCE { "room" } else { "personal" };
                let path = format!("/dav/calendars/{tenant}/{name}/{slug}/{UID}.ics");
                let handle = self.app.dav(&actor);
                let Ok(copy) = handle.get(&path).send().await else {
                    return notes;
                };
                if !copy.status.is_success() {
                    // No copy to edit: nothing to answer in a client.
                    return notes;
                }
                let text = answered(&copy.text(), &self.subject.address, partstat);
                match handle.put(&path, &text).send().await {
                    Ok(response) if response.status.is_success() => {}
                    Ok(response) => notes.push(problem("the answer in the calendar was refused", &response)),
                    Err(error) => notes.push(format!("the answer in the calendar cannot be sent: {error}")),
                }
            }
            ReplyChannel::Rsvp => {
                let Some(mailbox) = &self.subject.mailbox else {
                    return notes;
                };
                // The guest opens the link of the invitation they got by mail.
                let mails = self.app.mails().to(mailbox).await;
                let token = mails.iter().rev().find_map(|captured| {
                    let body = format!(
                        "{}\n{}",
                        captured.mail.text,
                        captured.mail.html.clone().unwrap_or_default()
                    );
                    rsvp_tokens_in(&body).pop()
                });
                let Some(token) = token else {
                    return notes;
                };
                let Ok(page) = self.app.rsvp().view(&token).send().await else {
                    return notes;
                };
                if !page.status.is_success() {
                    // A link that no longer works shows nothing to answer.
                    return notes;
                }
                let Some(csrf) = csrf_of(&page.text()) else {
                    notes.push("the RSVP page has no form to answer with".to_owned());
                    return notes;
                };
                let fields = [("partstat", partstat.as_ical()), ("csrf", csrf.as_str())];
                match self.app.rsvp().answer(&token, PUBLIC_BASE_URL, &fields).send().await {
                    Ok(response) if response.status.is_success() => {}
                    Ok(response) => notes.push(problem("the answer on the page was refused", &response)),
                    Err(error) => notes.push(format!("the answer on the page cannot be sent: {error}")),
                }
            }
            ReplyChannel::Inbound => {
                let Some(mailbox) = &self.subject.mailbox else {
                    return notes;
                };
                // The mail client of the attendee answers, and a gateway forwards the mail.
                let sequence = self.sequence_of_last_invitation().await;
                let ical = reply_ical(
                    UID,
                    &self.organizer_address(),
                    &self.subject.address,
                    partstat,
                    sequence,
                );
                let Ok(token) = self.app.tenant_token(Scope::ItipInbound) else {
                    notes.push("the world has no gateway token".to_owned());
                    return notes;
                };
                let body = json!({
                    "message_id": message_id,
                    "from": mailbox,
                    "ical": ical,
                    "dmarc": "pass",
                    "dkim": "pass"
                });
                let request = self
                    .app
                    .api(&token)
                    .post_json(&format!("/api/v1/tenants/{}/itip/inbound", names::TENANT), &body);
                match request {
                    Ok(pending) => match pending.send().await {
                        Ok(response) if response.status.is_success() => {}
                        Ok(response) => notes.push(problem("the gateway was refused", &response)),
                        Err(error) => notes.push(format!("the gateway cannot be reached: {error}")),
                    },
                    Err(error) => notes.push(error.to_string()),
                }
            }
        }
        notes
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

/// What the event is before the change and after it.
fn specs(case: SchedulingCase, subject: &Subject) -> (Option<Spec>, Spec) {
    let attendee = subject.address.clone();
    let cara = format!("mailto:{}@acme.example", names::GROUP_MEMBER);
    let base = Spec {
        attendees: vec![attendee.clone()],
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
                attendees: vec![cara, attendee],
                ..Spec::default()
            },
        ),
        Change::RemoveAttendee => (
            Some(Spec {
                attendees: vec![attendee, cara.clone()],
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

fn compare<T: PartialEq + core::fmt::Debug>(diffs: &mut Vec<String>, what: &str, actual: &T, expected: &T) {
    if actual != expected {
        diffs.push(format!("{what}: expected {expected:?}, got {actual:?}"));
    }
}

fn to_strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|text| (*text).to_owned()).collect()
}

/// Performs one case on an application of its own and returns what differs from the decision table (nothing when it
/// holds). Every surface runs for real: the MCP endpoint is part of the application, and a case it cannot answer is a
/// difference, not a case that is left out.
///
/// A case that differs and whose application had answered that it was too busy (a PostgreSQL server that other test processes
/// keep busy answers 503 now and then) is run again on a new application: the world of the first attempt is thrown away with
/// whatever the attempt did to it, so nothing is done twice. It is run at most [`busy::Policy::STANDARD`] times, and what the last
/// attempt differs in is the result. [`run_surface`] says which cases needed another attempt.
pub async fn run_case(case: SchedulingCase, number: usize, store: StoreKind) -> Vec<String> {
    run_case_again_when_busy(case, number, store).await.0
}

/// [`run_case`] with the number of times the case was run again.
async fn run_case_again_when_busy(case: SchedulingCase, number: usize, store: StoreKind) -> (Vec<String>, u32) {
    busy::repeat_while_busy(busy::Policy::STANDARD, || async {
        let (diffs, busy_answers) = run_case_once(case, number, store).await;
        let busy_effect = (!diffs.is_empty() && busy_answers > 0).then_some(busy::Effect::Discarded);
        busy::Attempt {
            value: diffs,
            busy: busy_effect,
        }
    })
    .await
}

/// Performs the case once on an application of its own: what differs, and how many answers of the application said that it was too
/// busy.
async fn run_case_once(case: SchedulingCase, number: usize, store: StoreKind) -> (Vec<String>, u32) {
    let scene = match Scene::new(&case, store).await {
        Ok(scene) => scene,
        Err(error) => return (vec![format!("the scene cannot be set up: {error}")], 0),
    };
    let diffs = perform(&scene, case, number).await;
    (diffs, scene.app.busy_answers())
}

/// Performs the case on `scene` and returns what differs from the decision table.
async fn perform(scene: &Scene, case: SchedulingCase, number: usize) -> Vec<String> {
    let wanted: Expected = expected(case);
    let mut diffs = Vec::new();
    let settle = || async {
        scene
            .app
            .run_workers_until_idle()
            .await
            .map(|_| ())
            .map_err(|error| format!("the workers do not settle: {error}"))
    };

    // 1. What the change is applied to.
    let (before, after) = specs(case, &scene.subject);
    if let Some(before) = &before {
        if let Err(error) = scene.write(before).await {
            return vec![format!("the event could not be created: {error}")];
        }
        if let Err(error) = settle().await {
            return vec![error];
        }
    }
    let mark = scene.app.events().unique().await.len();

    // 2. The change.
    let changed = match case.change {
        Change::Delete => scene.remove().await,
        Change::Move => scene.relocate().await,
        _ => scene.write(&after).await,
    };
    if let Err(error) = changed {
        return vec![format!("the change was refused: {error}")];
    }
    if let Err(error) = settle().await {
        return vec![error];
    }

    let seen = match scene.look().await {
        Ok(seen) => seen,
        Err(error) => return vec![format!("the result cannot be read: {error}")],
    };
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
    let message_id = format!("<case-{number}@example.net>");
    diffs.extend(scene.answer(case.reply, partstat_of(case.answer), &message_id).await);
    if let Err(error) = settle().await {
        diffs.push(error);
    }
    match scene.look().await {
        Ok(after_answer) => compare(
            &mut diffs,
            "PARTSTAT in the organizer's copy after the answer",
            &after_answer.partstat,
            &wanted.partstat_after_reply,
        ),
        Err(error) => diffs.push(format!("the result after the answer cannot be read: {error}")),
    }
    compare(
        &mut diffs,
        "scheduling events",
        &scene.scheduling_events_since(mark).await,
        &to_strings(&wanted.events),
    );
    diffs
}

/// The result of running the cases of one organizer surface.
#[derive(Debug, Clone, Default)]
pub struct SurfaceReport {
    /// How many cases ran.
    pub ran: usize,
    /// How many cases the sample left out ([`SchedulingCase::representative`]): none on the memory store, and on PostgreSQL
    /// none when `CONFORMANCE_FULL=1` asks for all of them.
    pub left_out: usize,
    /// The cases that differ from the table, with what differs.
    pub failures: Vec<(SchedulingCase, Vec<String>)>,
    /// The cases that were run again on a new application, and how many times, because they differed and their application had
    /// answered that it was too busy ([`run_case`]). A case that is in here and not in `failures` passed on a later attempt.
    pub reruns: Vec<(SchedulingCase, u32)>,
}

impl SurfaceReport {
    /// The failures as text, one case per paragraph; empty when the table holds.
    pub fn failure_text(&self) -> String {
        self.failures
            .iter()
            .map(|(case, diffs)| format!("  {case}\n      {}", diffs.join("\n      ")))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The cases that were run again, one per line; empty when none was.
    pub fn rerun_text(&self) -> String {
        self.reruns
            .iter()
            .map(|(case, times)| format!("  {case} (run again {times} times)"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Whether more cases were run again than a busy host explains ([`busy::excessive`]): a server that answers 503 now and then
    /// is a finding, not a flake.
    pub fn too_many_reruns(&self) -> bool {
        busy::excessive(self.reruns.len(), self.ran)
    }
}

/// Runs the cases of one surface, one after the other, and collects everything that differs. Every case runs, except on
/// PostgreSQL, where each costs a world of its own: there a representative subset runs ([`SchedulingCase::representative`])
/// unless `CONFORMANCE_FULL=1` asks for all of them, and the report says how many cases it left out.
pub async fn run_surface(surface: OrganizerSurface, store: StoreKind) -> SurfaceReport {
    let mut report = SurfaceReport::default();
    let cases: Vec<(usize, SchedulingCase)> = SchedulingCase::matrix()
        .into_iter()
        .enumerate()
        .filter(|(_, case)| case.organizer == surface)
        .collect();
    let cases = if RunOptions::for_store(store).sampling == Sampling::Everything {
        cases
    } else {
        let all = cases.len();
        let sample = SchedulingCase::representative(&cases.iter().map(|(_, case)| *case).collect::<Vec<_>>());
        let kept: Vec<(usize, SchedulingCase)> = cases.into_iter().filter(|(_, case)| sample.contains(case)).collect();
        report.left_out = all.saturating_sub(kept.len());
        kept
    };
    for (number, case) in cases {
        let (diffs, reruns) = run_case_again_when_busy(case, number, store).await;
        report.ran += 1;
        if reruns > 0 {
            report.reruns.push((case, reruns));
        }
        if !diffs.is_empty() {
            report.failures.push((case, diffs));
        }
    }
    report
}
