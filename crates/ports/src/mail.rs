//! The `MailTransport` port.
//!
//! The iMIP composer in the application layer builds an [`OutgoingMail`] (rendered template parts plus the iTIP
//! part); a transport delivers it. The SMTP adapter assembles RFC 5322 bytes with the `mime` crate and hands them to
//! a relay; the memory adapter captures the structured mail and its bytes for tests. Per-tenant variation (sender,
//! reply-to, locale) is data inside the mail, never a separate adapter instance.

use async_trait::async_trait;
use davhaven_domain::{MessageId, OutgoingMail};

use crate::error::PortError;

/// Proof that a transport accepted a mail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendReceipt {
    /// The `Message-ID` header of the mail as sent.
    pub message_id: MessageId,
    /// The relay's own identifier of the accepted message (for example the queue id of an SMTP 250 reply), when it
    /// reports one.
    pub transport_id: Option<String>,
}

/// Delivers outgoing mail.
#[async_trait]
pub trait MailTransport: Send + Sync {
    /// Sends one mail to all of its recipients.
    ///
    /// # Errors
    ///
    /// * `Unavailable` and `Timeout`: the relay cannot be reached or answers with a temporary failure; the outbox
    ///   retries.
    /// * `Rejected`: the relay refuses the sender or a recipient permanently (SMTP 5xx), or a staging safety rule
    ///   (`mail.allowed_recipient_domains`, circuit breaker) blocks the mail; the outbox does not retry.
    /// * `Invalid`: the mail cannot be encoded.
    async fn send(&self, mail: &OutgoingMail) -> Result<SendReceipt, PortError>;
}
