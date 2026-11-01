//! The `imip` handler over the in-memory store: composing the mail of a job (the invitation, the cancellation, the
//! reply), the people and the headers, the staging rules, the circuit breaker and the rate limit, and how failures
//! are classified. The template renderer and the calendar layer are doubles here; `imip_templates` runs the same
//! handler through the real renderer and the MIME assembler.

use std::sync::Arc;
use std::time::Duration;

use chrono::Duration as ChronoDuration;
use davhaven_testkit::davhaven_app::AppDeps;
use davhaven_testkit::davhaven_app::config::MailFromMode;
use davhaven_testkit::davhaven_app::imip::{
    BackendError, ImipHandler, REDIRECTED_FROM_HEADER, REPLY_SERVICE_FORM_TOTAL, send_budget,
};
use davhaven_testkit::davhaven_domain::{
    CalendarKind, CalendarUserAddress, DomainName, Email, EventData, HeaderText, ItipMethod, Locale, Mailbox,
    OutgoingMail,
};
use davhaven_testkit::davhaven_ports::{
    Clock as _, Database as _, HandlerError, ImipJob, OutboxHandler, OutboxMessage, OutboxRecord, PortError,
    TemplateName,
};
use secrecy::SecretString;
use serde_json::{Value, json};

use super::support::{FakeBackend, MetricsCapture, Seeded, World};

fn address(text: &str) -> CalendarUserAddress {
    CalendarUserAddress::parse(text).unwrap()
}

/// An event organized by `anna@example.org` with two attendees.
pub(crate) fn event(change: impl FnOnce(&mut Value)) -> EventData {
    let mut event = json!({
        "uid": "uid-1",
        "summary": "Planning <session>",
        "description": "Agenda",
        "location": "Room 4",
        "start": {"date_time": "2027-02-01T10:00:00", "time_zone": "Europe/Berlin"},
        "end": {"date_time": "2027-02-01T11:30:00", "time_zone": "Europe/Berlin"},
        "organizer": {"address": "mailto:anna@example.org"},
        "attendees": [
            {"address": "mailto:guest@example.net", "common_name": "Guest Example", "partstat": "needs_action"},
            {"address": "mailto:bob@example.org", "common_name": "Bob", "partstat": "accepted"}
        ]
    });
    change(&mut event);
    serde_json::from_value(event).unwrap()
}

pub(crate) struct Scenario {
    pub(crate) world: World,
    pub(crate) seeded: Seeded,
    pub(crate) backend: Arc<FakeBackend>,
    pub(crate) handler: ImipHandler,
}

impl Scenario {
    pub(crate) async fn new() -> Self {
        Self::with(|_| {}).await
    }

    pub(crate) async fn with(adjust: impl FnOnce(&mut AppDeps)) -> Self {
        let world = World::with(adjust);
        let seeded = world.seed().await;
        let backend = FakeBackend::new(event(|_| {}));
        let handler = ImipHandler::with_backend(world.core.clone(), backend.as_backend());
        Self {
            world,
            seeded,
            backend,
            handler,
        }
    }

    pub(crate) fn job(&self, method: ItipMethod, template: &str, recipient: &str) -> ImipJob {
        ImipJob {
            object: self.seeded.object.id,
            recipient: address(recipient),
            method,
            locale: Some(Locale::de()),
            template: TemplateName::parse(template).unwrap(),
            snapshot: None,
            replying_attendee: None,
            comment: None,
        }
    }

    pub(crate) fn invitation(&self) -> ImipJob {
        self.job(ItipMethod::Request, "imip_request", "mailto:guest@example.net")
    }

    pub(crate) async fn queue(&self, job: ImipJob) -> OutboxRecord {
        let id = self.world.enqueue(World::tenant(), OutboxMessage::Imip(job)).await;
        self.world.record(id).await
    }

    pub(crate) async fn run(&self, job: ImipJob) -> (OutboxRecord, Result<(), HandlerError>) {
        let record = self.queue(job).await;
        let result = self.handler.handle(&record).await;
        (record, result)
    }

    /// Sends the job and returns the one mail it produced.
    pub(crate) async fn send(&self, job: ImipJob) -> OutgoingMail {
        let before = self.world.mail.sent().len();
        let (_, result) = self.run(job).await;
        result.unwrap();
        let sent = self.world.mail.sent();
        assert_eq!(sent.len(), before + 1, "exactly one mail");
        sent.last().unwrap().clone()
    }

    /// The model of the last render.
    pub(crate) fn last_model(&self) -> Value {
        self.world.templates.requests().pop().unwrap().model
    }

    /// A reply job of bob@example.org, who answers the invitation of carol@example.net, about a copy that is gone.
    pub(crate) fn reply_of_a_deleted_copy(&self) -> ImipJob {
        let mut job = self.job(ItipMethod::Reply, "imip_reply", "mailto:carol@example.net");
        job.object = self.world.id();
        job.snapshot = Some("BOBS-COPY".to_owned());
        job.replying_attendee = Some(address("mailto:bob@example.org"));
        job
    }
}

fn name_of(mailbox: &Mailbox) -> Option<&str> {
    mailbox.name.as_ref().map(HeaderText::as_str)
}

fn header<'a>(mail: &'a OutgoingMail, name: &str) -> Option<&'a str> {
    mail.headers
        .iter()
        .find(|header| header.name.as_str().eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

#[tokio::test]
async fn an_invitation_is_composed_and_sent() {
    let scenario = Scenario::new().await;
    let (record, result) = scenario.run(scenario.invitation()).await;
    result.unwrap();

    let mail = scenario.world.mail.sent().pop().unwrap();
    assert_eq!(mail.message_id.as_str(), format!("<{}@mail.example.org>", record.id));
    assert_eq!(mail.from.address.as_str(), "noreply@mail.example.org");
    assert_eq!(name_of(&mail.from), Some("Anna Example via Example Organisation"));
    assert_eq!(mail.sender, None);
    let reply_to = mail.reply_to.as_ref().unwrap();
    assert_eq!(reply_to.address.as_str(), "anna@example.org");
    assert_eq!(name_of(reply_to), Some("Anna Example"));
    assert_eq!(mail.to.len(), 1);
    let to = mail.to.first().unwrap();
    assert_eq!(to.address.as_str(), "guest@example.net");
    assert_eq!(name_of(to), Some("Guest Example"));

    assert_eq!(
        mail.subject.as_str(),
        "imip_request (de, )",
        "no theme of the tenant: the renderer decides"
    );
    assert!(mail.html.as_deref().is_some_and(|html| html.starts_with("<p>")));
    assert_ne!(mail.text, "");
    let calendar = mail.calendar.as_ref().unwrap();
    assert_eq!(calendar.method, ItipMethod::Request);
    assert!(calendar.ics.contains("METHOD:REQUEST"));
    let attachment = mail.attachments.first().unwrap();
    assert_eq!(
        (attachment.filename.as_str(), attachment.content_type.as_str()),
        ("invite.ics", "application/ics")
    );
    assert_eq!(attachment.data, calendar.ics.as_bytes());

    assert_eq!(
        header(&mail, "Content-Class"),
        Some("urn:content-classes:calendarmessage")
    );
    assert_eq!(header(&mail, "Auto-Submitted"), Some("auto-generated"));
    assert_eq!(header(&mail, "X-Auto-Response-Suppress"), Some("OOF, AutoReply"));
    assert_eq!(header(&mail, REDIRECTED_FROM_HEADER), None);
    mail.validate().unwrap();
}

#[tokio::test]
async fn the_backend_gets_the_stored_object_and_the_recipient() {
    let scenario = Scenario::new().await;
    scenario.send(scenario.invitation()).await;
    let (source, request) = scenario.backend.requests().pop().unwrap();
    assert_eq!(source, "SOURCE");
    assert_eq!(request.method, ItipMethod::Request);
    assert_eq!(request.recipient, address("mailto:guest@example.net"));
    assert_eq!(request.replying_attendee, None);
}

#[tokio::test]
async fn the_template_is_rendered_in_the_theme_the_tenant_names() {
    let scenario = Scenario::new().await;
    let mut system = scenario.world.db.store().begin_system().await.unwrap();
    let mut tenant = system.tenants().get(World::tenant()).await.unwrap();
    tenant.settings.theme = Some("corporate".to_owned());
    let version = tenant.version;
    system.tenants().update(tenant, version).await.unwrap();
    system.commit().await.unwrap();

    scenario.send(scenario.invitation()).await;
    let request = scenario.world.templates.requests().pop().unwrap();
    assert_eq!(request.theme, "corporate");
}

#[tokio::test]
async fn the_template_gets_the_documented_model() {
    let scenario = Scenario::new().await;
    scenario.send(scenario.invitation()).await;
    let request = scenario.world.templates.requests().pop().unwrap();
    assert_eq!(request.template.as_str(), "imip_request");
    assert_eq!(request.locale, Locale::de());
    assert_eq!(
        request.theme, "",
        "a tenant that names no theme leaves the choice to the renderer (templates.default_theme)"
    );

    let model = request.model;
    let rsvp_url = model["rsvp_url"].as_str().unwrap().to_owned();
    assert!(
        rsvp_url.starts_with("https://cal.example.org/rsvp/dvh_rsvp_"),
        "{rsvp_url}"
    );
    assert_eq!(
        model,
        json!({
            "tenant": {"name": "Example Organisation"},
            "organizer": {"name": "Anna Example", "email": "anna@example.org"},
            "attendee": {"name": "Guest Example", "email": "guest@example.net"},
            "event": {
                "summary": "Planning <session>",
                "description": "Agenda",
                "location": "Room 4",
                "start": {"date": "2027-02-01", "time": "10:00", "zone": "Europe/Berlin"},
                "end": {"date": "2027-02-01", "time": "11:30", "zone": "Europe/Berlin"},
                "all_day": false,
                "recurring": false
            },
            "update": false,
            "rsvp_url": rsvp_url,
            "reply": null,
            "reply_to": "anna@example.org"
        })
    );
}

#[tokio::test]
async fn the_locale_of_the_job_wins_and_the_tenant_locale_is_the_fallback() {
    let scenario = Scenario::new().await;
    let mut job = scenario.invitation();
    job.locale = None;
    scenario.send(job).await;
    assert_eq!(
        scenario.world.templates.requests().pop().unwrap().locale,
        Locale::en(),
        "the tenant of the world speaks English"
    );
}

#[tokio::test]
async fn an_invitation_carries_a_link_that_survives_a_retry() {
    let scenario = Scenario::new().await;
    let (record, first) = scenario.run(scenario.invitation()).await;
    first.unwrap();
    scenario.handler.handle(&record).await.unwrap();

    let requests = scenario.world.templates.requests();
    assert_eq!(requests.len(), 2);
    let links: Vec<&str> = requests
        .iter()
        .map(|request| request.model["rsvp_url"].as_str().unwrap())
        .collect();
    assert_eq!(
        links[0], links[1],
        "the same link, so a mail that is sent twice says the same"
    );
    let sent = scenario.world.mail.sent();
    assert_eq!(sent.len(), 2);
    assert_eq!(
        sent[0].message_id, sent[1].message_id,
        "and carries the same Message-ID"
    );

    let rows = scenario.world.rsvp_tokens(scenario.seeded.object.id).await;
    assert_eq!(rows.len(), 1);
    let token = links[0].rsplit('/').next().unwrap();
    let row = rows.first().unwrap();
    let stored = davhaven_testkit::davhaven_ports::StoredHash::new(
        davhaven_testkit::davhaven_domain::CredentialKind::RsvpToken,
        row.pepper_kid.clone(),
        row.hash.clone(),
    );
    let secret = token.splitn(4, '_').nth(3).unwrap();
    let hasher = &scenario.world.core.deps().hasher;
    assert!(
        hasher.verify(&stored, &SecretString::from(secret.to_owned())),
        "the link authenticates like every other credential: prefix, then the hash of the secret component"
    );
    assert!(!hasher.verify(&stored, &SecretString::from(token.to_owned())));
}

#[tokio::test]
async fn a_later_version_of_the_invitation_is_marked_as_an_update() {
    let scenario = Scenario::new().await;
    scenario.backend.set_event(event(|event| event["sequence"] = json!(2)));
    let calendar = scenario.seeded.calendar.clone();
    scenario
        .world
        .bump_sequence(&calendar, &scenario.seeded.object, 2)
        .await;
    scenario.send(scenario.invitation()).await;
    assert_eq!(scenario.last_model()["update"], true);
}

#[tokio::test]
async fn an_old_invitation_that_is_still_queued_is_dropped_in_favor_of_the_newer_one() {
    let scenario = Scenario::new().await;
    // The stored object moved on to sequence 3; this mail is built from the first version.
    let calendar = scenario.seeded.calendar.clone();
    scenario
        .world
        .bump_sequence(&calendar, &scenario.seeded.object, 3)
        .await;
    let mut job = scenario.invitation();
    job.snapshot = Some("FIRST-VERSION".to_owned());
    scenario.backend.set_event(event(|event| event["sequence"] = json!(0)));
    let (_, result) = scenario.run(job).await;
    result.unwrap();
    assert_eq!(
        scenario.world.mail.sent(),
        Vec::new(),
        "the newer invitation is queued behind it; a mail that says less must not arrive after it"
    );
    assert_eq!(scenario.world.rsvp_tokens(scenario.seeded.object.id).await.len(), 0);

    // The same snapshot as the stored version is current, and does not claim to be an update.
    let scenario = Scenario::new().await;
    let mut job = scenario.invitation();
    job.snapshot = Some("FIRST-VERSION".to_owned());
    scenario.send(job).await;
    assert_eq!(scenario.backend.requests().pop().unwrap().0, "FIRST-VERSION");
    assert_eq!(
        scenario.last_model()["update"],
        false,
        "the version of the mail decides, not the stored object"
    );
}

#[tokio::test]
async fn an_invitation_for_somebody_who_is_no_attendee_any_more_is_dropped() {
    let metrics = MetricsCapture::default();
    let _installed = metrics::set_default_local_recorder(&metrics);
    let scenario = Scenario::new().await;
    let calendar = scenario.seeded.calendar.clone();
    scenario
        .world
        .set_attendees(&calendar, &scenario.seeded.object, &["mailto:bob@example.org"])
        .await;
    let (_, result) = scenario.run(scenario.invitation()).await;
    result.unwrap();
    assert_eq!(
        scenario.world.mail.sent(),
        Vec::new(),
        "the cancellation that removed them is queued on its own"
    );
    assert_eq!(
        scenario.world.rsvp_tokens(scenario.seeded.object.id).await.len(),
        0,
        "and no link was minted"
    );
    assert_eq!(
        metrics.get("davhaven_mail_dropped_total{reason=recipient_removed}"),
        Some(1.0)
    );

    // Somebody who is still on the list is invited.
    scenario
        .send(scenario.job(ItipMethod::Request, "imip_request", "mailto:bob@example.org"))
        .await;
}

#[tokio::test]
async fn a_cancellation_is_built_from_its_snapshot_and_survives_the_deletion_of_the_object() {
    let scenario = Scenario::new().await;
    scenario.world.delete_object(&scenario.seeded.object).await;
    let mut job = scenario.job(ItipMethod::Cancel, "imip_cancel", "mailto:guest@example.net");
    job.snapshot = Some("SNAPSHOT".to_owned());

    let mail = scenario.send(job).await;
    assert_eq!(mail.calendar.as_ref().unwrap().method, ItipMethod::Cancel);
    assert_eq!(mail.subject.as_str(), "imip_cancel (de, )");
    let (source, request) = scenario.backend.requests().pop().unwrap();
    assert_eq!(source, "SNAPSHOT");
    assert_eq!(
        request.stand_in_organizer,
        Some(address("mailto:noreply@mail.example.org")),
        "an organizer without a mail address is named by the sender address in a CANCEL as in a REQUEST"
    );
    assert_eq!(
        scenario.last_model()["rsvp_url"],
        Value::Null,
        "nobody answers a cancellation"
    );
    assert_eq!(
        scenario.world.rsvp_tokens(scenario.seeded.object.id).await.len(),
        0,
        "and no token is minted for it"
    );
}

#[tokio::test]
async fn messages_about_a_deleted_object_that_need_it_are_dropped() {
    let scenario = Scenario::new().await;
    scenario.world.delete_object(&scenario.seeded.object).await;
    for (method, template) in [
        (ItipMethod::Request, "imip_request"),
        (ItipMethod::Cancel, "imip_cancel"),
        (ItipMethod::Reply, "imip_reply"),
    ] {
        let (_, result) = scenario
            .run(scenario.job(method, template, "mailto:guest@example.net"))
            .await;
        result.unwrap();
    }
    assert_eq!(scenario.world.mail.sent(), Vec::new());
    assert_eq!(scenario.backend.requests(), Vec::new());

    // An invitation is about the stored object even when a snapshot exists: it needs the object for the link.
    let mut job = scenario.invitation();
    job.snapshot = Some("SNAPSHOT".to_owned());
    scenario.run(job).await.1.unwrap();
    assert_eq!(scenario.world.mail.sent(), Vec::new());
}

#[tokio::test]
async fn the_decline_of_a_deleted_attendee_copy_still_reaches_the_organizer() {
    let scenario = Scenario::new().await;
    scenario
        .world
        .add_principal(World::tenant(), "bob", "Bob Example")
        .await;
    scenario.backend.set_event(event(|event| {
        event["organizer"] = json!({"address": "mailto:carol@example.net", "common_name": "Carol External"});
        event["attendees"] = json!([
            {"address": "mailto:bob@example.org", "common_name": "Bob", "partstat": "declined"}
        ]);
    }));
    let job = scenario.reply_of_a_deleted_copy();
    assert!(
        scenario
            .world
            .read(World::tenant())
            .await
            .objects()
            .get_by_id(job.object)
            .await
            .is_err(),
        "the copy of the attendee is gone when the mail goes out"
    );

    let mail = scenario.send(job).await;
    assert_eq!(mail.calendar.as_ref().unwrap().method, ItipMethod::Reply);
    assert_eq!(name_of(&mail.from), Some("Bob Example via Example Organisation"));
    assert_eq!(mail.to.first().unwrap().address.as_str(), "carol@example.net");
    let (source, request) = scenario.backend.requests().pop().unwrap();
    assert_eq!(source, "BOBS-COPY", "built from the snapshot");
    assert_eq!(request.replying_attendee, Some(address("mailto:bob@example.org")));
    let model = scenario.last_model();
    assert_eq!(model["reply"], json!({"partstat": "DECLINED", "comment": null}));
    assert_eq!(
        model["attendee"],
        json!({"name": "Bob Example", "email": "bob@example.org"})
    );
}

#[tokio::test]
async fn a_reply_without_an_answering_attendee_or_without_an_answer_is_permanent() {
    let scenario = Scenario::new().await;
    scenario.backend.set_event(event(|event| {
        event["organizer"] = json!({"address": "mailto:carol@example.net"});
    }));

    let mut nameless = scenario.reply_of_a_deleted_copy();
    nameless.replying_attendee = None;
    let (_, result) = scenario.run(nameless).await;
    assert_eq!(
        result.unwrap_err(),
        HandlerError::permanent("the reply names no answering attendee")
    );

    // The attendee is on the event, but has not answered.
    let mut pending = scenario.reply_of_a_deleted_copy();
    pending.replying_attendee = Some(address("mailto:guest@example.net"));
    let (_, result) = scenario.run(pending).await;
    assert_eq!(
        result.unwrap_err(),
        HandlerError::permanent("the reply carries no answer of the attendee")
    );

    // The attendee is not on the event at all.
    let mut stranger = scenario.reply_of_a_deleted_copy();
    stranger.replying_attendee = Some(address("mailto:stranger@example.net"));
    let (_, result) = scenario.run(stranger).await;
    assert_eq!(
        result.unwrap_err(),
        HandlerError::permanent("the reply carries no answer of the attendee")
    );
    assert_eq!(scenario.world.mail.sent(), Vec::new());
}

#[tokio::test]
async fn the_comment_of_the_attendee_is_shown_to_the_organizer() {
    let scenario = Scenario::new().await;
    scenario.backend.set_event(event(|event| {
        event["organizer"] = json!({"address": "mailto:carol@example.net"});
    }));
    let mut job = scenario.reply_of_a_deleted_copy();
    job.comment = Some(format!("  Running late. {}", "x".repeat(600)));
    scenario.send(job).await;
    let model = scenario.last_model();
    let comment = model["reply"]["comment"].as_str().unwrap();
    assert!(comment.starts_with("Running late. x"), "{comment}");
    assert_eq!(comment.chars().count(), 501, "cut to 500 characters and an ellipsis");
}

#[tokio::test]
async fn a_reply_goes_to_the_organizer_on_behalf_of_the_answering_attendee() {
    let scenario = Scenario::new().await;
    let bob = scenario
        .world
        .add_principal(World::tenant(), "bob", "Bob Example")
        .await;
    let calendar = scenario
        .world
        .add_calendar(World::tenant(), bob.id, CalendarKind::Personal)
        .await;
    let copy = scenario
        .world
        .add_object(&calendar, &super::support::ObjectSpec::new("BOBS-COPY"))
        .await;
    scenario.backend.set_event(event(|event| {
        event["organizer"] = json!({"address": "mailto:carol@example.net", "common_name": "Carol External"});
    }));
    // Without a snapshot the reply is built from the stored copy.
    let mut job = scenario.job(ItipMethod::Reply, "imip_reply", "mailto:carol@example.net");
    job.object = copy.id;
    job.replying_attendee = Some(address("mailto:bob@example.org"));

    let mail = scenario.send(job).await;
    assert_eq!(name_of(&mail.from), Some("Bob Example via Example Organisation"));
    let reply_to = mail.reply_to.as_ref().unwrap();
    assert_eq!(reply_to.address.as_str(), "bob@example.org");
    let to = mail.to.first().unwrap();
    assert_eq!(
        (to.address.as_str(), name_of(to)),
        ("carol@example.net", Some("Carol External"))
    );
    assert_eq!(mail.calendar.as_ref().unwrap().method, ItipMethod::Reply);

    let (source, request) = scenario.backend.requests().pop().unwrap();
    assert_eq!(
        source, "BOBS-COPY",
        "the reply is built from the copy of the answering attendee"
    );
    assert_eq!(request.replying_attendee, Some(address("mailto:bob@example.org")));

    let model = scenario.last_model();
    assert_eq!(
        model["organizer"],
        json!({"name": "Carol External", "email": "carol@example.net"})
    );
    assert_eq!(
        model["attendee"],
        json!({"name": "Bob Example", "email": "bob@example.org"})
    );
    assert_eq!(model["reply"], json!({"partstat": "ACCEPTED", "comment": null}));
    assert_eq!(model["rsvp_url"], Value::Null);
    assert_eq!(scenario.world.rsvp_tokens(copy.id).await.len(), 0);
}

#[tokio::test]
async fn replies_in_the_service_form_are_counted_and_replies_from_the_attendee_are_not() {
    let metrics = MetricsCapture::default();
    let _installed = metrics::set_default_local_recorder(&metrics);
    let scenario = Scenario::with(|deps| deps.config.mail.from_mode = MailFromMode::Organizer).await;
    scenario.backend.set_event(event(|event| {
        event["organizer"] = json!({"address": "mailto:carol@example.net"});
    }));
    let service = scenario.send(scenario.reply_of_a_deleted_copy()).await;
    assert_eq!(service.from.address.as_str(), "noreply@mail.example.org");
    assert_eq!(
        metrics.get(REPLY_SERVICE_FORM_TOTAL),
        Some(1.0),
        "bob@example.org is outside mail.example.org"
    );

    scenario
        .world
        .update_tenant(|tenant| tenant.settings.sender.domain = Some(DomainName::parse("example.org").unwrap()))
        .await;
    let own = scenario.send(scenario.reply_of_a_deleted_copy()).await;
    assert_eq!(
        own.from.address.as_str(),
        "bob@example.org",
        "the attendee is the sender"
    );
    assert_eq!(own.sender.as_ref().unwrap().address.as_str(), "noreply@example.org");
    assert_eq!(metrics.get(REPLY_SERVICE_FORM_TOTAL), Some(1.0), "not counted again");
    scenario.backend.set_event(event(|_| {}));
    scenario.send(scenario.invitation()).await;
    assert_eq!(
        metrics.get(REPLY_SERVICE_FORM_TOTAL),
        Some(1.0),
        "invitations are not replies"
    );
}

#[tokio::test]
async fn staging_mail_is_dropped_for_recipients_outside_the_allowed_domains() {
    let metrics = MetricsCapture::default();
    let _installed = metrics::set_default_local_recorder(&metrics);
    let scenario = Scenario::with(|deps| {
        deps.config.mail.allowed_recipient_domains = vec![DomainName::parse("example.org").unwrap()];
    })
    .await;

    let (_, result) = scenario.run(scenario.invitation()).await;
    result.unwrap();
    assert_eq!(
        scenario.world.mail.sent(),
        Vec::new(),
        "guest@example.net is outside example.org"
    );
    assert_eq!(scenario.backend.requests(), Vec::new(), "nothing is even prepared");
    assert_eq!(
        metrics.get("davhaven_mail_dropped_total{reason=recipient_domain}"),
        Some(1.0)
    );

    let inside = scenario.job(ItipMethod::Request, "imip_request", "mailto:bob@example.org");
    scenario.send(inside).await;
    assert_eq!(metrics.get("davhaven_mail_sent_total{method=request}"), Some(1.0));
}

#[tokio::test]
async fn staging_mail_can_be_redirected_to_one_address() {
    let scenario = Scenario::with(|deps| {
        deps.config.mail.redirect_all_to = Some(Email::parse("qa@example.org").unwrap());
    })
    .await;
    let mail = scenario.send(scenario.invitation()).await;
    assert_eq!(mail.to.len(), 1);
    assert_eq!(mail.to.first().unwrap().address.as_str(), "qa@example.org");
    assert_eq!(mail.to.first().unwrap().name, None);
    assert_eq!(header(&mail, REDIRECTED_FROM_HEADER), Some("guest@example.net"));
    assert_eq!(
        mail.calendar.as_ref().unwrap().method,
        ItipMethod::Request,
        "the rest is untouched"
    );
}

#[tokio::test]
async fn organizer_mode_sends_from_the_organizer_inside_the_sender_domain_only() {
    let scenario = Scenario::with(|deps| deps.config.mail.from_mode = MailFromMode::Organizer).await;
    // anna@example.org is not in mail.example.org: the service form is used.
    let service = scenario.send(scenario.invitation()).await;
    assert_eq!(service.from.address.as_str(), "noreply@mail.example.org");
    assert!(service.reply_to.is_some() && service.sender.is_none());

    // The sender domain of the tenant moves to example.org: now the organizer is inside it.
    scenario
        .world
        .update_tenant(|tenant| tenant.settings.sender.domain = Some(DomainName::parse("example.org").unwrap()))
        .await;
    let own = scenario.send(scenario.invitation()).await;
    assert_eq!(own.from.address.as_str(), "anna@example.org");
    assert_eq!(name_of(&own.from), Some("Anna Example"));
    assert_eq!(own.sender.as_ref().unwrap().address.as_str(), "noreply@example.org");
    assert_eq!(own.reply_to, None, "From is the organizer already");
    assert_eq!(own.message_id.as_str().rsplit('@').next(), Some("example.org>"));
}

#[tokio::test]
async fn the_sender_name_of_the_tenant_replaces_its_display_name() {
    let scenario = Scenario::new().await;
    scenario
        .world
        .update_tenant(|tenant| tenant.settings.sender.display_name = Some("Calendar Team".to_owned()))
        .await;
    let mail = scenario.send(scenario.invitation()).await;
    assert_eq!(name_of(&mail.from), Some("Anna Example via Calendar Team"));
    assert_eq!(scenario.last_model()["tenant"]["name"], "Calendar Team");
}

#[tokio::test]
async fn organizers_without_a_principal_are_named_by_the_event() {
    let scenario = Scenario::new().await;
    scenario.backend.set_event(event(|event| {
        event["organizer"] = json!({"address": "mailto:dave@partner.example", "common_name": "Dave Partner"});
    }));
    let mail = scenario.send(scenario.invitation()).await;
    assert_eq!(name_of(&mail.from), Some("Dave Partner via Example Organisation"));
    assert_eq!(mail.reply_to.as_ref().unwrap().address.as_str(), "dave@partner.example");
}

#[tokio::test]
async fn an_address_is_never_the_display_name_of_the_sender() {
    // An organizer the event does not name: the sender name is the tenant's, not "anonymous@partner.example via ...".
    let scenario = Scenario::new().await;
    scenario.backend.set_event(event(|event| {
        event["organizer"] = json!({"address": "mailto:anonymous@partner.example"});
    }));
    let anonymous = scenario.send(scenario.invitation()).await;
    assert_eq!(name_of(&anonymous.from), Some("Example Organisation"));
    assert_eq!(
        anonymous.reply_to.as_ref().unwrap().address.as_str(),
        "anonymous@partner.example",
        "replies still reach the organizer"
    );
    // The template still gets something to call the organizer by.
    assert_eq!(scenario.last_model()["organizer"]["name"], "anonymous@partner.example");
}

#[tokio::test]
async fn the_template_learns_whether_a_reply_to_the_mail_reaches_a_person() {
    // The organizer has an address: the service form carries it as the Reply-To, and the footer can say where replies go.
    let scenario = Scenario::new().await;
    let mail = scenario.send(scenario.invitation()).await;
    assert_eq!(mail.reply_to.as_ref().unwrap().address.as_str(), "anna@example.org");
    assert_eq!(scenario.last_model()["reply_to"], "anna@example.org");

    // An organizer without an address of their own (a service account is known by an urn:uuid) leaves no Reply-To: the mail
    // comes from the no-reply address of the tenant, and the footer must not tell the reader to reply to it.
    scenario.backend.set_event(event(|event| {
        event["organizer"] =
            json!({"address": "urn:uuid:018f3c1e-7b2a-7c3d-9e4f-0123456789ab", "common_name": "Course plan"});
    }));
    let service = scenario.send(scenario.invitation()).await;
    assert_eq!(service.reply_to, None);
    assert_eq!(service.from.address.as_str(), "noreply@mail.example.org");
    assert_eq!(scenario.last_model()["reply_to"], Value::Null);
    // The backend is asked to name that organizer by the address the mail comes from, which is where a guest's client sends
    // its answer (the iCalendar of the mail would otherwise carry the `urn:uuid` of the principal).
    let (_, request) = scenario.backend.requests().pop().unwrap();
    assert_eq!(
        request.stand_in_organizer,
        Some(address("mailto:noreply@mail.example.org"))
    );

    // The answer of an attendee goes out in the name of the attendee: that is the person a reply reaches, and the organizer of
    // the message is the recipient, whom nothing stands in for.
    let reply = scenario.reply_of_a_deleted_copy();
    scenario.send(reply).await;
    assert_eq!(scenario.last_model()["reply_to"], "bob@example.org");
    let (_, request) = scenario.backend.requests().pop().unwrap();
    assert_eq!(request.stand_in_organizer, None);
}

#[tokio::test]
async fn in_the_name_of_the_organizer_the_from_is_the_person_a_reply_reaches() {
    let scenario = Scenario::with(|deps| deps.config.mail.from_mode = MailFromMode::Organizer).await;
    scenario
        .world
        .update_tenant(|tenant| tenant.settings.sender.domain = Some(DomainName::parse("example.org").unwrap()))
        .await;
    let own = scenario.send(scenario.invitation()).await;
    assert_eq!(own.reply_to, None, "From is the organizer already");
    assert_eq!(scenario.last_model()["reply_to"], "anna@example.org");
}

#[tokio::test]
async fn a_long_name_cannot_push_the_via_out_of_the_header() {
    let scenario = Scenario::new().await;
    scenario.backend.set_event(event(|event| {
        event["organizer"] = json!({
            "address": "mailto:dave@partner.example",
            "common_name": "D".repeat(300)
        });
    }));
    scenario
        .world
        .update_tenant(|tenant| tenant.settings.sender.display_name = Some("T".repeat(300)))
        .await;
    let mail = scenario.send(scenario.invitation()).await;
    let name = name_of(&mail.from).unwrap();
    assert_eq!(
        name,
        format!("{} via {}", "D".repeat(80), "T".repeat(80)),
        "both parts are shortened before they are joined"
    );
}

#[tokio::test]
async fn display_names_never_break_out_of_their_header() {
    let scenario = Scenario::new().await;
    scenario
        .world
        .rename(scenario.seeded.organizer.id, "Anna\r\nBcc: victim@example.net")
        .await;
    let mail = scenario.send(scenario.invitation()).await;
    let name = mail.from.name.as_ref().unwrap().as_str();
    assert!(!name.chars().any(char::is_control), "{name:?}");
    assert!(name.starts_with("Anna  Bcc: victim@example.net"), "{name:?}");
}

#[tokio::test]
async fn configuration_and_data_problems_are_permanent() {
    let scenario = Scenario::new().await;

    // A recipient without an e-mail address.
    let (_, result) = scenario
        .run(scenario.job(
            ItipMethod::Request,
            "imip_request",
            "urn:uuid:00000000-0000-0000-0000-000000000009",
        ))
        .await;
    assert_eq!(
        result.unwrap_err(),
        HandlerError::permanent("the recipient has no e-mail address")
    );

    // An event without organizer or start.
    scenario.backend.set_event(event(|event| {
        event.as_object_mut().unwrap().remove("organizer");
    }));
    let (_, result) = scenario.run(scenario.invitation()).await;
    assert_eq!(
        result.unwrap_err(),
        HandlerError::permanent("the event has no organizer")
    );
    scenario.backend.set_event(event(|event| {
        event.as_object_mut().unwrap().remove("start");
        event.as_object_mut().unwrap().remove("end");
    }));
    let (_, result) = scenario.run(scenario.invitation()).await;
    assert_eq!(result.unwrap_err(), HandlerError::permanent("the event has no start"));

    // A tenant without a sender domain.
    scenario.backend.set_event(event(|_| {}));
    scenario
        .world
        .update_tenant(|tenant| tenant.settings.sender.domain = None)
        .await;
    let (_, result) = scenario.run(scenario.invitation()).await;
    assert_eq!(
        result.unwrap_err(),
        HandlerError::permanent("the tenant has no sender domain")
    );
    assert_eq!(scenario.world.mail.sent(), Vec::new());
}

#[tokio::test]
async fn a_missing_tenant_is_not_an_error() {
    let scenario = Scenario::new().await;
    let record = scenario.queue(scenario.invitation()).await;
    scenario.world.delete_tenant().await;
    scenario.handler.handle(&record).await.unwrap();
    assert_eq!(scenario.world.mail.sent(), Vec::new());
}

#[tokio::test]
async fn calendar_and_template_failures_are_classified() {
    let scenario = Scenario::new().await;
    scenario
        .backend
        .fail_with(Some(BackendError::Invalid("no VEVENT".to_owned())));
    let (_, result) = scenario.run(scenario.invitation()).await;
    assert_eq!(
        result.unwrap_err(),
        HandlerError::permanent("the calendar data cannot be turned into a message")
    );
    scenario
        .backend
        .fail_with(Some(BackendError::Unavailable("not implemented".to_owned())));
    let (_, result) = scenario.run(scenario.invitation()).await;
    assert_eq!(
        result.unwrap_err(),
        HandlerError::retryable("the calendar layer is not available")
    );
    scenario.backend.fail_with(None);

    scenario
        .world
        .templates
        .fail_with(PortError::invalid("no such template"));
    let (_, result) = scenario.run(scenario.invitation()).await;
    assert_eq!(
        result.unwrap_err(),
        HandlerError::permanent("the template could not be rendered")
    );
    scenario
        .world
        .templates
        .fail_with(PortError::unavailable("themes unreadable"));
    let (_, result) = scenario.run(scenario.invitation()).await;
    assert_eq!(
        result.unwrap_err(),
        HandlerError::retryable("the template renderer is not available")
    );
    assert_eq!(scenario.world.mail.sent(), Vec::new());
}

#[tokio::test]
async fn relay_failures_are_classified_and_never_leak_addresses() {
    let scenario = Scenario::new().await;
    let cases = [
        (
            PortError::unavailable("421 relay busy for guest@example.net"),
            HandlerError::retryable("the mail relay is not available"),
        ),
        (
            PortError::timeout("timed out talking to relay"),
            HandlerError::retryable("the mail relay is not available"),
        ),
        (
            PortError::rejected("550 5.1.1 <guest@example.net> user unknown"),
            HandlerError::permanent("the mail relay refused the message"),
        ),
        (
            PortError::invalid("header too long"),
            HandlerError::permanent("the message cannot be encoded"),
        ),
    ];
    for (error, expected) in cases {
        scenario.world.mail.fail_next(error);
        let (_, result) = scenario.run(scenario.invitation()).await;
        let actual = result.unwrap_err();
        assert_eq!(actual, expected);
        assert!(!actual.message().contains("guest@example.net"));
    }
    assert_eq!(scenario.world.mail.sent(), Vec::new());
}

#[tokio::test]
async fn the_breaker_holds_mail_back_while_the_relay_is_down() {
    let metrics = MetricsCapture::default();
    let _installed = metrics::set_default_local_recorder(&metrics);
    let scenario = Scenario::with(|deps| deps.config.mail.max_consecutive_failures = 2).await;
    for _ in 0..2 {
        scenario.world.mail.fail_next(PortError::unavailable("relay down"));
        let (_, result) = scenario.run(scenario.invitation()).await;
        assert_eq!(
            result.unwrap_err(),
            HandlerError::retryable("the mail relay is not available")
        );
    }

    // Open: the next mail is not even offered to the relay, and it is deferred, not failed.
    let (_, result) = scenario.run(scenario.invitation()).await;
    assert_eq!(
        result.unwrap_err(),
        HandlerError::defer(Duration::from_secs(30), "the mail relay is not answering"),
        "the cooldown is the outbox backoff base"
    );
    assert_eq!(scenario.world.mail.sent(), Vec::new());
    assert_eq!(metrics.get("davhaven_mail_held_total{reason=breaker_open}"), Some(1.0));
    assert_eq!(
        metrics.get("davhaven_mail_failed_total{reason=breaker_open}"),
        None,
        "a hold is no failure"
    );

    // After the cooldown (the outbox backoff base) a probe goes out and closes the breaker.
    scenario.world.clock.advance(ChronoDuration::seconds(31));
    scenario.send(scenario.invitation()).await;
    scenario.send(scenario.invitation()).await;
}

#[tokio::test]
async fn a_mail_that_has_waited_for_a_week_stops_being_deferred() {
    let scenario = Scenario::with(|deps| deps.config.mail.max_consecutive_failures = 1).await;
    scenario.world.mail.fail_next(PortError::unavailable("relay down"));
    scenario.run(scenario.invitation()).await.1.unwrap_err();
    let young = scenario.queue(scenario.invitation()).await;
    assert!(
        scenario.handler.handle(&young).await.unwrap_err().is_deferred(),
        "a young mail waits for the relay"
    );

    let mut old = scenario.queue(scenario.invitation()).await;
    old.created_at = scenario.world.clock.now() - ChronoDuration::days(8);
    assert_eq!(
        scenario.handler.handle(&old).await.unwrap_err(),
        HandlerError::retryable("the mail relay is not answering"),
        "after a week a hold counts like a failure, so the attempts run out one day"
    );
}

#[tokio::test(start_paused = true)]
async fn a_send_that_hangs_ends_inside_the_budget_and_counts_against_the_breaker() {
    let scenario = Scenario::with(|deps| deps.config.mail.max_consecutive_failures = 1).await;
    // The default lease is a minute: the send may take 36 s, the dispatcher gives the handler 48 s.
    assert_eq!(
        send_budget(&scenario.world.core.deps().config.outbox),
        Duration::from_secs(36)
    );
    scenario.world.mail.hang_next();
    let (_, result) = scenario.run(scenario.invitation()).await;
    assert_eq!(
        result.unwrap_err(),
        HandlerError::retryable("the mail relay is not available")
    );
    let (_, result) = scenario.run(scenario.invitation()).await;
    assert!(result.unwrap_err().is_deferred(), "the timeout opened the breaker");
}

#[tokio::test]
async fn a_refusal_shows_that_the_relay_works() {
    let scenario = Scenario::with(|deps| deps.config.mail.max_consecutive_failures = 2).await;
    for _ in 0..5 {
        scenario.world.mail.fail_next(PortError::unavailable("relay down"));
        scenario.run(scenario.invitation()).await.1.unwrap_err();
        scenario.world.mail.fail_next(PortError::rejected("550 no such user"));
        scenario.run(scenario.invitation()).await.1.unwrap_err();
    }
    scenario.send(scenario.invitation()).await;
}

#[tokio::test]
async fn the_rate_limit_holds_mail_back_until_the_bucket_refills() {
    let scenario = Scenario::with(|deps| deps.config.mail.rate_limit_per_minute = 2).await;
    scenario.send(scenario.invitation()).await;
    scenario.send(scenario.invitation()).await;
    let (_, result) = scenario.run(scenario.invitation()).await;
    assert_eq!(
        result.unwrap_err(),
        HandlerError::defer(Duration::from_secs(30), "the mail rate limit holds the mail back"),
        "the next of two tokens a minute takes 30 s"
    );
    assert_eq!(scenario.world.mail.sent().len(), 2);

    scenario.world.clock.advance(ChronoDuration::seconds(30));
    scenario.send(scenario.invitation()).await;
}

#[tokio::test]
async fn the_shared_limiter_holds_mail_back_for_as_long_as_it_says() {
    let scenario = Scenario::new().await;
    scenario.world.limiter.deny_next(Duration::from_secs(45));
    let (_, result) = scenario.run(scenario.invitation()).await;
    assert_eq!(
        result.unwrap_err(),
        HandlerError::defer(Duration::from_secs(45), "the mail rate limit holds the mail back"),
        "a deferral with the retry_after of the limiter, which uses up no attempt"
    );
    assert_eq!(scenario.world.mail.sent(), Vec::new());
    let checks = scenario.world.limiter.checks();
    assert_eq!(checks.len(), 1);
    assert_eq!(
        (checks[0].0.bucket, checks[0].1),
        ("mail", 1),
        "the `mail` bucket of the port"
    );

    scenario.send(scenario.invitation()).await;

    // A limiter that is down does not stop the mail.
    scenario.world.limiter.break_down();
    scenario.send(scenario.invitation()).await;
}

#[tokio::test]
async fn records_of_other_kinds_and_versions_are_refused_without_guessing() {
    let scenario = Scenario::new().await;
    let record = scenario.queue(scenario.invitation()).await;

    let mut foreign = record.clone();
    foreign.kind = "webhook".to_owned();
    assert!(!scenario.handler.handle(&foreign).await.unwrap_err().is_retryable());

    let mut newer = record.clone();
    newer.schema_version = 99;
    let error = scenario.handler.handle(&newer).await.unwrap_err();
    assert_eq!(
        error,
        HandlerError::retryable("the payload was written by a newer version")
    );

    let mut damaged = record;
    damaged.payload = json!({"object": "not-a-uuid", "recipient": "ann@example.org"});
    let error = scenario.handler.handle(&damaged).await.unwrap_err();
    assert!(!error.is_retryable());
    assert_eq!(
        error.message(),
        "the payload of the record cannot be decoded",
        "a static text: the payload names people"
    );
    assert_eq!(scenario.world.mail.sent(), Vec::new());
}

#[tokio::test]
async fn a_store_outage_is_retried() {
    let scenario = Scenario::new().await;
    let record = scenario.queue(scenario.invitation()).await;
    scenario.world.db.set_outage(true);
    assert!(scenario.handler.handle(&record).await.unwrap_err().is_retryable());
}

#[tokio::test]
async fn the_metrics_count_what_happened() {
    let metrics = MetricsCapture::default();
    let _installed = metrics::set_default_local_recorder(&metrics);
    let scenario = Scenario::new().await;
    scenario.send(scenario.invitation()).await;
    scenario.world.mail.fail_next(PortError::rejected("550"));
    scenario.run(scenario.invitation()).await.1.unwrap_err();
    scenario.world.mail.fail_next(PortError::unavailable("421"));
    scenario.run(scenario.invitation()).await.1.unwrap_err();

    assert_eq!(metrics.get("davhaven_mail_sent_total{method=request}"), Some(1.0));
    assert_eq!(metrics.get("davhaven_mail_failed_total{reason=rejected}"), Some(1.0));
    assert_eq!(metrics.get("davhaven_mail_failed_total{reason=unavailable}"), Some(1.0));
}

#[tokio::test]
async fn all_day_events_are_described_without_times() {
    let scenario = Scenario::new().await;
    scenario.backend.set_event(event(|event| {
        event["start"] = json!({"date": "2027-02-01"});
        event["end"] = json!({"date": "2027-02-04"});
    }));
    scenario.send(scenario.invitation()).await;
    let model = scenario.last_model();
    assert_eq!(model["event"]["all_day"], true);
    assert_eq!(
        model["event"]["start"],
        json!({"date": "2027-02-01", "time": null, "zone": null})
    );
    assert_eq!(
        model["event"]["end"],
        json!({"date": "2027-02-03", "time": null, "zone": null})
    );
}

#[tokio::test]
async fn the_handler_serves_the_imip_kind_and_limits_attempts() {
    let scenario = Scenario::new().await;
    assert_eq!(scenario.handler.kind(), "imip");
    assert!(scenario.handler.limits_attempts());
    assert!(format!("{:?}", scenario.handler).contains("ImipHandler"));
}
