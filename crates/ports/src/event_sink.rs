//! The `EventSink` port receiving domain events after commit.
//!
//! The outbox dispatcher fans every committed [`Envelope`] out to all configured sinks (the `log` sink of
//! `hooks-webhook` writes it to the structured log) and expands webhook deliveries for matching subscriptions.
//! Delivery is at-least-once and unordered, so sinks deduplicate on the envelope id.

use async_trait::async_trait;
use davhaven_domain::Envelope;

use crate::error::HandlerError;

/// A destination for domain events.
#[async_trait]
pub trait EventSink: Send + Sync {
    /// The name of the sink as selected in `plugins.event_sinks`, for logs and metrics.
    fn name(&self) -> &'static str;

    /// Delivers one event.
    ///
    /// # Errors
    ///
    /// [`HandlerError::Retryable`] makes the dispatcher deliver the event again with backoff;
    /// [`HandlerError::Permanent`] drops it for this sink.
    async fn deliver(&self, envelope: &Envelope) -> Result<(), HandlerError>;
}
