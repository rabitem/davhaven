//! The seam between the iMIP composer and the rest of the mail path: the models the handler builds are rendered by
//! the real template renderer (strict undefined behavior, German and English) and the result is assembled into MIME
//! by the real mail transport of the memory adapter. A model that drifts from what the themes expect shows up
//! here as a permanent "the template could not be rendered" instead of in production as a dead letter.

use std::sync::Arc;

use davhaven_testkit::davhaven_domain::{ItipMethod, Locale};
use davhaven_testkit::davhaven_mail_memory::config::MemoryMailConfig;
use davhaven_testkit::davhaven_mail_memory::transport::{CapturedMail, MemoryMailTransport};
use davhaven_testkit::davhaven_ports::ImipJob;
use davhaven_testkit::davhaven_templates::config::{MiniJinjaConfig, TemplatesConfig};
use davhaven_testkit::davhaven_templates::renderer::MiniJinjaRenderer;
use serde_json::{Value, json};

use super::imip_mail::{Scenario, event};
use super::support::RecordingRenderer;

/// A scenario whose handler renders with the real renderer and sends through the memory transport.
async fn scenario() -> (Scenario, Arc<MemoryMailTransport>, Arc<RecordingRenderer>) {
    let mut parts = None;
    let scenario = Scenario::with(|deps| {
        // The year and the date of the themes follow the clock of the world, not the day the test runs.
        let renderer = MiniJinjaRenderer::new(
            &TemplatesConfig::default(),
            &MiniJinjaConfig::default(),
            Arc::clone(&deps.clock),
        )
        .unwrap();
        let recording = RecordingRenderer::new(Arc::new(renderer));
        deps.templates = Arc::<RecordingRenderer>::clone(&recording);
        let memory = Arc::new(MemoryMailTransport::new(
            Arc::clone(&deps.clock),
            &MemoryMailConfig::default(),
        ));
        deps.mail = Arc::<MemoryMailTransport>::clone(&memory);
        parts = Some((memory, recording));
    })
    .await;
    let (memory, recording) = parts.unwrap();
    (scenario, memory, recording)
}

/// The events the mails are about: the shapes that make a template take a different branch.
fn events() -> Vec<(&'static str, Value)> {
    let full = json!({
        "uid": "uid-1",
        "summary": "Planning <session> & more",
        "description": "Agenda:\n- one\n- two",
        "location": "Room 4",
        "start": {"date_time": "2027-02-01T10:00:00", "time_zone": "Europe/Berlin"},
        "end": {"date_time": "2027-02-01T11:30:00", "time_zone": "Europe/Berlin"},
        "organizer": {"address": "mailto:anna@example.org"},
        "attendees": [
            {"address": "mailto:guest@example.net", "common_name": "Guest Example", "partstat": "needs_action"},
            {"address": "mailto:bob@example.org", "common_name": "Bob", "partstat": "accepted"}
        ]
    });
    let change = |change: &dyn Fn(&mut Value)| {
        let mut copy = full.clone();
        change(&mut copy);
        copy
    };
    vec![
        ("a full event", full.clone()),
        (
            "an event without description, location and end",
            change(&|event| {
                for key in ["description", "location", "end"] {
                    event.as_object_mut().unwrap().remove(key);
                }
            }),
        ),
        (
            "an all-day event of several days",
            change(&|event| {
                event["start"] = json!({"date": "2027-02-01"});
                event["end"] = json!({"date": "2027-02-04"});
            }),
        ),
        (
            "a single all-day event",
            change(&|event| {
                event["start"] = json!({"date": "2027-02-01"});
                event["end"] = json!({"date": "2027-02-02"});
            }),
        ),
        (
            "a recurring event in UTC",
            change(&|event| {
                event["start"] = json!({"date_time": "2027-02-01T09:00:00Z"});
                event["end"] = json!({"date_time": "2027-02-01T10:00:00Z"});
                event["recurrence"] = json!({"rrule": "FREQ=WEEKLY;COUNT=4"});
            }),
        ),
        (
            "an event on a floating time with a duration",
            change(&|event| {
                event["start"] = json!({"date_time": "2027-02-01T09:00:00"});
                event.as_object_mut().unwrap().remove("end");
                event["duration"] = json!("PT45M");
            }),
        ),
        ("an update", change(&|event| event["sequence"] = json!(3))),
    ]
}

/// Runs the job through the handler; the mail ends up in the memory transport.
async fn deliver(scenario: &Scenario, job: ImipJob) {
    let (_, result) = scenario.run(job).await;
    result.unwrap();
}

fn mime_of(mail: &CapturedMail) -> String {
    mail.mime_text()
}

#[tokio::test]
async fn every_invitation_renders_in_both_languages_and_assembles() {
    let (scenario, transport, models) = scenario().await;
    for locale in [Locale::de(), Locale::en()] {
        for (name, shape) in events() {
            let updated = shape["sequence"] == json!(3);
            scenario.backend.set_event(event(|event| *event = shape.clone()));
            if updated {
                let calendar = scenario.seeded.calendar.clone();
                scenario
                    .world
                    .bump_sequence(&calendar, &scenario.seeded.object, 3)
                    .await;
            }
            let mut job = scenario.invitation();
            job.locale = Some(locale.clone());
            let (_, result) = scenario.run(job).await;
            result.unwrap_or_else(|error| panic!("{locale} {name}: {error}"));
            let captured = transport
                .last()
                .await
                .unwrap_or_else(|| panic!("{locale} {name}: no mail"));
            let mail = &captured.mail;
            assert!(!mail.subject.as_str().trim().is_empty(), "{locale} {name}");
            assert!(!mail.text.trim().is_empty(), "{locale} {name}");
            let html = mail.html.as_deref().unwrap_or_default();
            assert!(
                html.contains("Planning &lt;session&gt; &amp; more"),
                "{locale} {name}: escaped summary in {html}"
            );
            assert!(
                mail.text.contains("Planning <session> & more"),
                "{locale} {name}: the plain text is not escaped"
            );
            let rsvp = models.last_model()["rsvp_url"].as_str().unwrap().to_owned();
            assert!(
                mail.text.contains(&rsvp) && html.contains(&rsvp),
                "{locale} {name}: the RSVP link is in both parts"
            );
            let mime = mime_of(&captured);
            assert!(mime.contains("multipart/alternative"), "{locale} {name}");
            assert!(
                mime.contains("method=REQUEST"),
                "{locale} {name}: the text/calendar part carries the method"
            );
            assert!(mime.contains("invite.ics"), "{locale} {name}");
            assert!(
                mime.contains("Content-Class: urn:content-classes:calendarmessage"),
                "{locale} {name}"
            );
        }
    }
}

#[tokio::test]
async fn an_update_says_so_in_the_subject() {
    let (scenario, transport, _models) = scenario().await;
    let mut subjects = Vec::new();
    for sequence in [0, 3] {
        scenario
            .backend
            .set_event(event(|event| event["sequence"] = json!(sequence)));
        let calendar = scenario.seeded.calendar.clone();
        scenario
            .world
            .bump_sequence(&calendar, &scenario.seeded.object, sequence)
            .await;
        let mut job = scenario.invitation();
        job.locale = Some(Locale::en());
        deliver(&scenario, job).await;
        subjects.push(transport.last().await.unwrap().mail.subject.as_str().to_owned());
    }
    assert_ne!(subjects[0], subjects[1], "{subjects:?}");
}

#[tokio::test]
async fn cancellations_and_replies_render_in_both_languages_and_assemble() {
    let (scenario, transport, _models) = scenario().await;
    scenario
        .world
        .add_principal(
            davhaven_testkit::davhaven_domain::TenantId::from_uuid(uuid::Uuid::from_u128(super::support::TENANT)),
            "bob",
            "Bob Example",
        )
        .await;
    for locale in [Locale::de(), Locale::en()] {
        // A cancellation survives the deletion of its object: it is built from the snapshot.
        scenario.backend.set_event(event(|_| {}));
        let mut cancel = scenario.job(ItipMethod::Cancel, "imip_cancel", "mailto:guest@example.net");
        cancel.locale = Some(locale.clone());
        cancel.snapshot = Some("SNAPSHOT".to_owned());
        deliver(&scenario, cancel).await;
        let captured = transport.last().await.unwrap();
        assert!(mime_of(&captured).contains("method=CANCEL"), "{locale}");
        assert!(!captured.mail.text.trim().is_empty() && !captured.mail.subject.as_str().trim().is_empty());
        assert!(
            !captured.mail.text.contains("dvh_rsvp_"),
            "{locale}: nobody answers a cancellation, so the mail has no link"
        );

        // Every answer, with and without a comment.
        for (partstat, comment) in [
            ("accepted", None),
            ("declined", Some("Sorry, <b>no</b>")),
            ("tentative", Some("Maybe")),
        ] {
            scenario.backend.set_event(event(|event| {
                event["organizer"] = json!({"address": "mailto:carol@example.net", "common_name": "Carol External"});
                event["attendees"] = json!([
                    {"address": "mailto:bob@example.org", "common_name": "Bob", "partstat": partstat}
                ]);
            }));
            let mut reply = scenario.reply_of_a_deleted_copy();
            reply.locale = Some(locale.clone());
            reply.comment = comment.map(str::to_owned);
            deliver(&scenario, reply).await;
            let captured = transport.last().await.unwrap();
            let mime = mime_of(&captured);
            assert!(mime.contains("method=REPLY"), "{locale} {partstat}");
            assert_eq!(captured.mail.to[0].address.as_str(), "carol@example.net");
            assert!(!captured.mail.text.trim().is_empty(), "{locale} {partstat}");
            if let Some(comment) = comment {
                assert!(
                    captured.mail.text.contains(comment),
                    "{locale} {partstat}: the comment is in the text"
                );
                assert!(
                    !captured.mail.html.as_deref().unwrap_or_default().contains("<b>no</b>"),
                    "{locale} {partstat}: the comment is escaped in the HTML part"
                );
            }
        }
    }
}

#[tokio::test]
async fn the_models_of_the_handler_are_the_models_the_catalog_checks_the_themes_with() {
    // The default theme is checked against `Template::sample_models` at startup. The models of the handler must have
    // the same shape: the same keys at every level, so that what the themes may use is what the handler provides.
    use davhaven_testkit::davhaven_templates::catalog::Template;
    fn shape(value: &Value) -> Value {
        match value {
            Value::Object(map) => Value::Object(map.iter().map(|(key, value)| (key.clone(), shape(value))).collect()),
            Value::Array(_) => json!("array"),
            Value::Null => json!("null"),
            Value::String(_) => json!("string"),
            Value::Bool(_) => json!("bool"),
            Value::Number(_) => json!("number"),
        }
    }
    fn keys(value: &Value, prefix: &str, out: &mut Vec<String>) {
        if let Value::Object(map) = value {
            for (key, value) in map {
                out.push(format!("{prefix}{key}"));
                keys(value, &format!("{prefix}{key}."), out);
            }
        }
    }
    let _ = shape;
    let (scenario, _, models) = scenario().await;
    deliver(&scenario, scenario.invitation()).await;
    let handled = models.last_model();
    let mut handled_keys = Vec::new();
    keys(&handled, "", &mut handled_keys);
    handled_keys.sort();
    let mut sample_keys = Vec::new();
    keys(&Template::ImipRequest.sample_model(), "", &mut sample_keys);
    sample_keys.sort();
    assert_eq!(
        handled_keys, sample_keys,
        "the invitation model of the handler and the sample of the catalog"
    );
}
