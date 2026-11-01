use std::io;
use std::sync::{Arc, PoisonError};

use chrono::{TimeZone, Utc};
use davhaven_domain::events::CalendarPayload;
use davhaven_domain::{AuditActor, CalendarKind, EventId, EventPayload, EventType, TenantId};
use tracing_subscriber::fmt::MakeWriter;
use uuid::Uuid;

use super::*;

#[expect(clippy::disallowed_types, reason = "a test writer that locks for an instant")]
type Buffer = std::sync::Mutex<Vec<u8>>;

#[derive(Clone, Default)]
struct Capture(Arc<Buffer>);

impl Capture {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap_or_else(PoisonError::into_inner)).into_owned()
    }
}

impl io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn envelope() -> Envelope {
    Envelope::new(
        EventId::from_uuid(Uuid::from_u128(0x0190_0000_0000_7000_8000_0000_0000_0abc)),
        EventType::CalendarCreated,
        TenantId::from_uuid(Uuid::from_u128(0x7e)),
        Utc.with_ymd_and_hms(2027, 1, 1, 12, 0, 0).unwrap(),
        AuditActor::system(),
        EventPayload::Calendar(CalendarPayload {
            calendar: davhaven_domain::CalendarId::from_uuid(Uuid::from_u128(0x0c0f_fee0)),
            owner: davhaven_domain::PrincipalId::from_uuid(Uuid::from_u128(0x0b0b_0b0b)),
            kind: CalendarKind::Group,
        }),
    )
    .unwrap()
}

#[tokio::test]
async fn an_event_becomes_one_line_with_ids_and_no_payload() {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_ansi(false)
        .finish();
    let _installed = tracing::subscriber::set_default(subscriber);

    LogSink.deliver(&envelope()).await.unwrap();

    let text = capture.text();
    assert_eq!(text.lines().count(), 1, "{text}");
    for expected in [
        "davhaven::events",
        "domain event",
        "event_id=01900000-0000-7000-8000-000000000abc",
        "event_type=\"calendar.created\"",
        "tenant=00000000-0000-0000-0000-00000000007e",
        "occurred_at=2027-01-01T12:00:00+00:00",
        "actor_kind=System",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    for payload in ["0c0ffee0", "0b0b0b0b", "Group", "group"] {
        assert!(
            !text.contains(payload),
            "the payload stays out of the log ({payload}): {text}"
        );
    }
}

#[tokio::test]
async fn a_repeated_event_is_logged_again_with_the_same_id() {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_ansi(false)
        .finish();
    let _installed = tracing::subscriber::set_default(subscriber);
    for _ in 0..2 {
        LogSink.deliver(&envelope()).await.unwrap();
    }
    let text = capture.text();
    assert_eq!(
        text.matches("event_id=01900000-0000-7000-8000-000000000abc").count(),
        2,
        "{text}"
    );
}

#[tokio::test]
async fn the_sink_keeps_the_port_contract() {
    assert_eq!(LogSink.name(), "log");
    davhaven_port_tests::event_sink::run_all(|| Arc::new(LogSink)).await;
}
