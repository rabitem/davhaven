//! The `log` event sink: one structured log line per domain event.
//!
//! The line carries the ids and the type of the event (`event_id`, `event_type`, `tenant`, the actor), never its
//! payload: logs carry ids only (`ENGINEERING_RULES` R8). Delivery is at-least-once, so the same event can be
//! logged twice; the `event_id` identifies repeats.

use async_trait::async_trait;
use davhaven_domain::Envelope;
use davhaven_ports::{EventSink, HandlerError, PortLabel, observe};

/// The name of the sink in `plugins.event_sinks`.
pub const PLUGIN: &str = "log";

const LABEL: PortLabel = PortLabel::new("event_sink", PLUGIN);

/// The `log` sink.
#[derive(Debug, Clone, Copy, Default)]
pub struct LogSink;

#[async_trait]
impl EventSink for LogSink {
    fn name(&self) -> &'static str {
        PLUGIN
    }

    async fn deliver(&self, envelope: &Envelope) -> Result<(), HandlerError> {
        observe(LABEL, "deliver", async {
            tracing::info!(
                target: "davhaven::events",
                event_id = %envelope.id,
                event_type = envelope.event_type.as_str(),
                version = envelope.version,
                tenant = %envelope.tenant,
                occurred_at = %envelope.occurred_at.to_rfc3339(),
                actor_kind = ?envelope.actor.kind,
                actor_principal = ?envelope.actor.principal_id,
                "domain event"
            );
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests;
