//! The capturing `MailTransport` implementation.
//!
//! [`MemoryMailTransport`] delivers nothing: it assembles every mail with `davhaven-mime` (so a mail that cannot
//! be encoded fails here like it would at a relay), keeps the structured mail together with the RFC 5322 bytes
//! and the SMTP envelope, and hands them to tests and developers. The capture is bounded: when it holds
//! `max_messages` mails the oldest are dropped first.

use std::collections::VecDeque;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{Email, OutgoingMail};
use davhaven_mime::message::assemble;
use davhaven_ports::{Clock, MailTransport, PortError, PortLabel, SendReceipt, observe};
use tokio::sync::Mutex;

use crate::config::{MemoryMailConfig, PLUGIN};

/// The label of the adapter in metrics and spans.
const LABEL: PortLabel = PortLabel::new("mail_transport", PLUGIN);

/// A mail the transport accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedMail {
    /// The mail as the composer built it.
    pub mail: OutgoingMail,
    /// The RFC 5322 message a relay would have received.
    pub mime: Vec<u8>,
    /// The SMTP `MAIL FROM`.
    pub envelope_from: Email,
    /// The SMTP `RCPT TO` addresses.
    pub envelope_to: Vec<Email>,
    /// When the transport accepted the mail (from the clock).
    pub accepted_at: DateTime<Utc>,
}

impl CapturedMail {
    /// The message as text, with invalid UTF-8 replaced (the message is 7-bit clean in practice).
    pub fn mime_text(&self) -> String {
        String::from_utf8_lossy(&self.mime).into_owned()
    }
}

#[derive(Debug, Default)]
struct State {
    mails: VecDeque<CapturedMail>,
    accepted: u64,
}

/// A `MailTransport` that captures instead of sending.
#[derive(Clone)]
pub struct MemoryMailTransport {
    clock: Arc<dyn Clock>,
    max_messages: usize,
    state: Arc<Mutex<State>>,
}

impl core::fmt::Debug for MemoryMailTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemoryMailTransport")
            .field("max_messages", &self.max_messages)
            .finish_non_exhaustive()
    }
}

impl MemoryMailTransport {
    /// A transport that stamps mails with `clock` and keeps at most `config.max_messages` of them.
    pub fn new(clock: Arc<dyn Clock>, config: &MemoryMailConfig) -> Self {
        Self {
            clock,
            max_messages: config.max_messages.max(1),
            state: Arc::default(),
        }
    }

    /// The captured mails, oldest first.
    pub async fn sent(&self) -> Vec<CapturedMail> {
        self.state.lock().await.mails.iter().cloned().collect()
    }

    /// How many mails are captured.
    pub async fn len(&self) -> usize {
        self.state.lock().await.mails.len()
    }

    /// Whether nothing is captured.
    pub async fn is_empty(&self) -> bool {
        self.state.lock().await.mails.is_empty()
    }

    /// The mail accepted last.
    pub async fn last(&self) -> Option<CapturedMail> {
        self.state.lock().await.mails.back().cloned()
    }

    /// The captured mails addressed to `address` (case-insensitive), oldest first.
    pub async fn to(&self, address: &str) -> Vec<CapturedMail> {
        let wanted = address.to_ascii_lowercase();
        self.state
            .lock()
            .await
            .mails
            .iter()
            .filter(|captured| captured.envelope_to.iter().any(|to| to.as_str() == wanted))
            .cloned()
            .collect()
    }

    /// Removes and returns the captured mails, oldest first.
    pub async fn take(&self) -> Vec<CapturedMail> {
        self.state.lock().await.mails.drain(..).collect()
    }

    /// Forgets the captured mails.
    pub async fn clear(&self) {
        self.state.lock().await.mails.clear();
    }

    async fn accept(&self, mail: &OutgoingMail) -> Result<SendReceipt, PortError> {
        let accepted_at = self.clock.now();
        let assembled = assemble(mail, accepted_at).map_err(|error| PortError::invalid(error.to_string()))?;
        let envelope_from = assembled.envelope_from().clone();
        let envelope_to = assembled.envelope_to().to_vec();
        let mime = assembled.into_bytes();

        let mut state = self.state.lock().await;
        state.accepted += 1;
        let transport_id = format!("memory-{}", state.accepted);
        state.mails.push_back(CapturedMail {
            mail: mail.clone(),
            mime,
            envelope_from,
            envelope_to,
            accepted_at,
        });
        while state.mails.len() > self.max_messages {
            state.mails.pop_front();
        }
        Ok(SendReceipt {
            message_id: mail.message_id.clone(),
            transport_id: Some(transport_id),
        })
    }
}

#[async_trait]
impl MailTransport for MemoryMailTransport {
    async fn send(&self, mail: &OutgoingMail) -> Result<SendReceipt, PortError> {
        observe(LABEL, "send", self.accept(mail)).await
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use davhaven_domain::{HeaderName, HeaderText, Mailbox, MessageId};
    use davhaven_ports::PortErrorKind;
    use davhaven_ports::testing::ManualClock;

    use super::*;

    fn email(text: &str) -> Email {
        Email::parse(text).unwrap()
    }

    fn mail(n: u32, to: &[&str]) -> OutgoingMail {
        OutgoingMail {
            message_id: MessageId::parse(&format!("<m{n}@mail.example.org>")).unwrap(),
            from: Mailbox::bare(email("noreply@mail.example.org")),
            sender: None,
            reply_to: None,
            to: to.iter().map(|address| Mailbox::bare(email(address))).collect(),
            subject: HeaderText::parse("Hello").unwrap(),
            text: "Hi\n".to_owned(),
            html: None,
            calendar: None,
            attachments: Vec::new(),
            headers: Vec::new(),
        }
    }

    fn transport(max: usize) -> (MemoryMailTransport, ManualClock) {
        let clock = ManualClock::default();
        let transport = MemoryMailTransport::new(Arc::new(clock.clone()), &MemoryMailConfig { max_messages: max });
        (transport, clock)
    }

    #[tokio::test]
    async fn accepted_mails_are_captured_with_their_bytes_and_envelope() {
        let (transport, clock) = transport(10);
        let first = transport.send(&mail(1, &["a@example.net"])).await.unwrap();
        clock.advance(Duration::minutes(5));
        let second = transport
            .send(&mail(2, &["b@example.net", "c@example.net"]))
            .await
            .unwrap();
        assert_eq!(first.message_id.as_str(), "<m1@mail.example.org>");
        assert_eq!(first.transport_id.as_deref(), Some("memory-1"));
        assert_eq!(second.transport_id.as_deref(), Some("memory-2"));

        let sent = transport.sent().await;
        assert_eq!(sent.len(), 2);
        assert_eq!(transport.len().await, 2);
        assert!(!transport.is_empty().await);
        assert_eq!(sent[0].envelope_to, vec![email("a@example.net")]);
        assert_eq!(sent[1].envelope_to.len(), 2);
        assert_eq!(sent[0].envelope_from, email("noreply@mail.example.org"));
        assert!(
            sent[0]
                .mime_text()
                .starts_with("Date: Fri, 01 Jan 2027 00:00:00 +0000\r\n"),
            "{}",
            sent[0].mime_text()
        );
        assert!(
            sent[1]
                .mime_text()
                .starts_with("Date: Fri, 01 Jan 2027 00:05:00 +0000\r\n")
        );
        assert_eq!(sent[1].mail, mail(2, &["b@example.net", "c@example.net"]));
        assert_eq!(
            transport.last().await.unwrap().mail.message_id.as_str(),
            "<m2@mail.example.org>"
        );
    }

    #[tokio::test]
    async fn the_capture_is_bounded_and_drops_the_oldest_first() {
        let (transport, _) = transport(2);
        for n in 1..=3 {
            transport.send(&mail(n, &["a@example.net"])).await.unwrap();
        }
        let ids: Vec<String> = transport
            .sent()
            .await
            .iter()
            .map(|m| m.mail.message_id.to_string())
            .collect();
        assert_eq!(ids, vec!["<m2@mail.example.org>", "<m3@mail.example.org>"]);
        let receipt = transport.send(&mail(4, &["a@example.net"])).await.unwrap();
        assert_eq!(
            receipt.transport_id.as_deref(),
            Some("memory-4"),
            "the counter keeps counting"
        );
    }

    #[tokio::test]
    async fn lookups_by_recipient_take_and_clear() {
        let (transport, _) = transport(10);
        transport.send(&mail(1, &["a@example.net"])).await.unwrap();
        transport.send(&mail(2, &["b@example.net"])).await.unwrap();
        transport
            .send(&mail(3, &["a@example.net", "b@example.net"]))
            .await
            .unwrap();
        assert_eq!(transport.to("A@Example.NET").await.len(), 2);
        assert_eq!(transport.to("nobody@example.net").await.len(), 0);
        let taken = transport.take().await;
        assert_eq!(taken.len(), 3);
        assert!(transport.is_empty().await);
        transport.send(&mail(4, &["a@example.net"])).await.unwrap();
        transport.clear().await;
        assert_eq!(transport.len().await, 0);
        assert!(transport.last().await.is_none());
    }

    #[tokio::test]
    async fn mails_that_cannot_be_encoded_are_refused_and_not_captured() {
        let (transport, _) = transport(10);
        let none = mail(1, &[]);
        assert_eq!(transport.send(&none).await.unwrap_err().kind, PortErrorKind::Invalid);
        let mut reserved = mail(2, &["a@example.net"]);
        reserved.headers.push(davhaven_domain::ExtraHeader {
            name: HeaderName::parse("Message-ID").unwrap(),
            value: HeaderText::parse("<x@y>").unwrap(),
        });
        assert_eq!(
            transport.send(&reserved).await.unwrap_err().kind,
            PortErrorKind::Invalid
        );
        assert!(transport.is_empty().await);
    }

    #[tokio::test]
    async fn the_adapter_passes_the_mail_contract() {
        davhaven_port_tests::mail::run_all(|| Arc::new(transport(100).0)).await;
    }

    #[test]
    fn debug_output_shows_no_mail() {
        let (transport, _) = transport(5);
        assert_eq!(format!("{transport:?}"), "MemoryMailTransport { max_messages: 5, .. }");
    }
}
