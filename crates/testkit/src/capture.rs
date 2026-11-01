//! Capture doubles for the side effects a test observes: sent mails and delivered domain events.
//!
//! [`MailCapture`] is a `MailTransport` that keeps every mail it is given, together with the RFC 5322 message a relay
//! would have received (it is the capturing transport of `davhaven-mail-memory`, so a mail that cannot be assembled fails
//! here like it would at a relay); [`EventCapture`] is an `EventSink` that keeps every envelope. A
//! [`TestApp`](crate::app::TestApp) hands both to the application it builds (they are part of its `AppDeps`: the mail
//! transport and one of the event sinks), and the tests read them through `app.mails()` and `app.events()`. The matrices
//! assert "no side effects on denial" by comparing [`Snapshot`]s taken before and after a denied request.

use std::sync::Arc;

use async_trait::async_trait;
use davhaven_domain::{Envelope, EventType, OutgoingMail};
use davhaven_mail_memory::config::MemoryMailConfig;
use davhaven_mail_memory::transport::MemoryMailTransport;
use davhaven_ports::{Clock, EventSink, HandlerError, MailTransport, PortError, SendReceipt};
use tokio::sync::Mutex;

pub use davhaven_mail_memory::transport::CapturedMail;

/// A `MailTransport` that captures instead of sending.
#[derive(Debug, Clone)]
pub struct MailCapture {
    transport: MemoryMailTransport,
}

impl MailCapture {
    /// An empty capture that stamps mails with `clock`.
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            transport: MemoryMailTransport::new(clock, &MemoryMailConfig::default()),
        }
    }

    /// Every captured mail in sending order.
    pub async fn all(&self) -> Vec<CapturedMail> {
        self.transport.sent().await
    }

    /// The number of captured mails.
    pub async fn count(&self) -> usize {
        self.transport.len().await
    }

    /// The captured mails addressed to `address` (compared case-insensitively).
    pub async fn to(&self, address: &str) -> Vec<CapturedMail> {
        self.transport.to(address).await
    }

    /// The last captured mail.
    pub async fn last(&self) -> Option<CapturedMail> {
        self.transport.last().await
    }

    /// Forgets everything captured so far.
    pub async fn clear(&self) {
        self.transport.clear().await;
    }
}

#[async_trait]
impl MailTransport for MailCapture {
    async fn send(&self, mail: &OutgoingMail) -> Result<SendReceipt, PortError> {
        self.transport.send(mail).await
    }
}

/// An `EventSink` that keeps every envelope it is given.
#[derive(Debug, Clone, Default)]
pub struct EventCapture {
    delivered: Arc<Mutex<Vec<Envelope>>>,
}

impl EventCapture {
    /// An empty capture.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every delivery in order; an envelope delivered twice (at-least-once) appears twice.
    pub async fn all(&self) -> Vec<Envelope> {
        self.delivered.lock().await.clone()
    }

    /// The deliveries without repeats: the first delivery of every envelope id.
    pub async fn unique(&self) -> Vec<Envelope> {
        let delivered = self.delivered.lock().await;
        let mut seen = Vec::new();
        let mut unique = Vec::new();
        for envelope in delivered.iter() {
            if !seen.contains(&envelope.id) {
                seen.push(envelope.id);
                unique.push(envelope.clone());
            }
        }
        unique
    }

    /// The distinct events of one type.
    pub async fn of_type(&self, event_type: EventType) -> Vec<Envelope> {
        self.unique()
            .await
            .into_iter()
            .filter(|envelope| envelope.event_type == event_type)
            .collect()
    }

    /// The number of distinct events.
    pub async fn count(&self) -> usize {
        self.unique().await.len()
    }

    /// Forgets everything captured so far.
    pub async fn clear(&self) {
        self.delivered.lock().await.clear();
    }
}

#[async_trait]
impl EventSink for EventCapture {
    fn name(&self) -> &'static str {
        "capture"
    }

    async fn deliver(&self, envelope: &Envelope) -> Result<(), HandlerError> {
        self.delivered.lock().await.push(envelope.clone());
        Ok(())
    }
}

/// What a test can observe of the side effects so far; compare two snapshots to assert that a request changed
/// nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    /// The number of captured mails.
    pub mails: usize,
    /// The number of distinct captured events.
    pub events: usize,
}

impl Snapshot {
    /// Takes a snapshot of the captures.
    pub async fn take(mails: &MailCapture, events: &EventCapture) -> Self {
        Self {
            mails: mails.count().await,
            events: events.count().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use davhaven_port_tests::{event_sink, mail};
    use davhaven_ports::testing::ManualClock;

    use super::*;

    fn capture() -> MailCapture {
        MailCapture::new(Arc::new(ManualClock::default()))
    }

    #[tokio::test]
    async fn the_mail_capture_satisfies_the_mail_contract() {
        mail::run_all(|| Arc::new(capture())).await;
    }

    #[tokio::test]
    async fn the_event_capture_satisfies_the_event_sink_contract() {
        event_sink::run_all(|| Arc::new(EventCapture::new())).await;
    }

    #[tokio::test]
    async fn mails_are_kept_in_order_with_their_bytes_and_found_by_recipient() {
        let capture = capture();
        let first = mail::sample_mail(1, &["Guest@Elsewhere.example"]).unwrap();
        let second = mail::sample_mail(2, &["other@elsewhere.example"]).unwrap();
        capture.send(&first).await.unwrap();
        capture.send(&second).await.unwrap();
        assert_eq!(capture.count().await, 2);
        assert_eq!(capture.to("guest@elsewhere.example").await.len(), 1);
        assert_eq!(capture.to("nobody@elsewhere.example").await.len(), 0);
        assert_eq!(capture.last().await.unwrap().mail, second);
        let all = capture.all().await;
        assert_eq!(all[0].mail.message_id, first.message_id);
        assert!(
            all[0].mime_text().contains("Message-ID"),
            "the message a relay would get is kept"
        );
        let before = Snapshot::take(&capture, &EventCapture::new()).await;
        assert_eq!(before, Snapshot { mails: 2, events: 0 });
        capture.clear().await;
        assert_eq!(capture.count().await, 0);
    }

    #[tokio::test]
    async fn events_are_deduplicated_by_id_and_filtered_by_type() {
        let capture = EventCapture::new();
        let calendar = event_sink::calendar_created(1).unwrap();
        let principal = event_sink::principal_created(2).unwrap();
        for envelope in [&calendar, &calendar, &principal] {
            capture.deliver(envelope).await.unwrap();
        }
        assert_eq!(capture.all().await.len(), 3, "every delivery is kept");
        assert_eq!(capture.count().await, 2, "distinct events are counted once");
        assert_eq!(capture.of_type(EventType::CalendarCreated).await, vec![calendar]);
        assert_eq!(capture.of_type(EventType::PrincipalDeleted).await, Vec::new());
        capture.clear().await;
        assert_eq!(capture.unique().await, Vec::new());
    }
}
