//! Registration of the adapters in the plugin registry.
//!
//! * `outbox_handler` `webhook`: delivers webhooks (Standard Webhooks); configured by the `[webhooks]` table, which
//!   the server passes as the `webhook` table of the plugin tree. Needs the database and the HTTP client.
//! * `outbox_handler` `noop`: takes the `webhook` kind and completes every delivery without sending, marking the
//!   delivery `dead`. Needs the database.
//! * `event_sink` `log`: writes every domain event to the structured log.

use std::sync::Arc;

use davhaven_ports::{
    Built, EventSink, OutboxHandler, PluginCheck, PluginContext, PluginDescriptor, PluginError, PluginRegistry,
    PortKind, parse_config,
};
use futures::future::BoxFuture;
use schemars::{JsonSchema, Schema};
use serde::Deserialize;

use crate::config::{PLUGIN as WEBHOOK, WebhooksConfig};
use crate::log_sink::{self, LogSink};
use crate::webhook::{NoopWebhookHandler, WebhookHandler};

/// The name of the `noop` handler.
pub const NOOP: &str = "noop";

/// The configuration of plugins that have none: an empty table, and a typo is still an error.
#[derive(Debug, Clone, Copy, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmptyConfig {}

/// Registers `webhook`, `noop` and `log`.
///
/// # Errors
///
/// [`PluginError::DuplicateName`] when the registry has one of them already.
pub fn register(registry: &mut PluginRegistry) -> Result<(), PluginError> {
    registry.register(
        PortKind::OUTBOX_HANDLER,
        PluginDescriptor::new(
            WEBHOOK,
            "Delivers domain events to webhook subscriptions as signed HTTPS requests (Standard Webhooks), retried \
             with backoff until the retry window ends.",
            webhook_schema,
            build_webhook,
        )
        .with_dedicated_table(TABLE)
        .with_check(check_webhook),
    )?;
    registry.register(
        PortKind::OUTBOX_HANDLER,
        PluginDescriptor::new(
            NOOP,
            "Takes webhook deliveries and completes them without sending anything (they are marked dead, so the API \
             shows that nothing was sent). For deployments that do not use webhooks.",
            empty_schema,
            build_noop,
        ),
    )?;
    registry.register(
        PortKind::EVENT_SINK,
        PluginDescriptor::new(
            log_sink::PLUGIN,
            "Writes every domain event to the structured log: ids and type, never the payload.",
            empty_schema,
            build_log,
        ),
    )
}

/// The dedicated table of the `webhook` handler besides `[plugin.outbox_handler.webhook]` (PLAN F0.9).
pub const TABLE: &str = "webhooks";

/// The table of the `webhook` handler as a validated configuration: the one reading that `build` and the check of
/// `davhaven config check` share, so that the check says what `serve` will say.
fn config(table: serde_json::Value) -> Result<WebhooksConfig, PluginError> {
    let config: WebhooksConfig = parse_config(WEBHOOK, table)?;
    config.validate()?;
    Ok(config)
}

/// The check of `davhaven config check`: the table parses and validates as `build` would have it.
///
/// # Errors
///
/// [`PluginError::InvalidConfig`] naming the key.
fn check_webhook(check: &PluginCheck<'_>) -> Result<Vec<String>, PluginError> {
    config(check.table.clone())?;
    Ok(Vec::new())
}

fn webhook_schema() -> Schema {
    schemars::schema_for!(WebhooksConfig)
}

fn empty_schema() -> Schema {
    schemars::schema_for!(EmptyConfig)
}

fn build_webhook(
    context: PluginContext,
    table: serde_json::Value,
) -> BoxFuture<'static, Result<Built<dyn OutboxHandler>, PluginError>> {
    Box::pin(async move {
        let config = config(table)?;
        let handler: Arc<dyn OutboxHandler> = Arc::new(WebhookHandler::from_context(&context, config)?);
        Ok(Built::new(handler))
    })
}

fn build_noop(
    context: PluginContext,
    config: serde_json::Value,
) -> BoxFuture<'static, Result<Built<dyn OutboxHandler>, PluginError>> {
    Box::pin(async move {
        let EmptyConfig {} = parse_config(NOOP, config)?;
        let handler: Arc<dyn OutboxHandler> = Arc::new(NoopWebhookHandler::from_context(&context)?);
        Ok(Built::new(handler))
    })
}

fn build_log(
    _context: PluginContext,
    config: serde_json::Value,
) -> BoxFuture<'static, Result<Built<dyn EventSink>, PluginError>> {
    Box::pin(async move {
        let EmptyConfig {} = parse_config(log_sink::PLUGIN, config)?;
        let sink: Arc<dyn EventSink> = Arc::new(LogSink);
        Ok(Built::new(sink))
    })
}

#[cfg(test)]
mod tests;
