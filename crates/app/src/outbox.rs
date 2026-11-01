//! The outbox: the dispatcher that delivers what the application queued in its transactions, the fan-out of domain
//! events, operator access to the queue and the management of webhook subscriptions.
//!
//! # Pieces
//!
//! | Piece | What it does |
//! | --- | --- |
//! | [`OutboxDispatcher`] | The worker (`outbox`): claims ready records of all tenants, runs the handler of their kind, retries with exponential backoff, dead-letters, publishes the queue gauges and releases its leases on shutdown. |
//! | [`DomainEventHandler`] | The `domain_event` handler: one webhook delivery per matching subscription (with the details of managed and group calendar objects when asked for), then the event sinks. |
//! | [`OutboxServiceImpl`] | `GET …/outbox` and the retry of dead items. |
//! | [`WebhookServiceImpl`] | Webhook subscriptions, secret rotation, ping, deliveries and redelivery. |
//!
//! The handler of the `webhook` kind lives in the `hooks-webhook` adapter; the application's own are `domain_event`
//! (here), `imip` ([`crate::imip`]) and `internal_delivery` ([`crate::itip`]). [`handlers`] collects those of this
//! crate and [`new_dispatcher`] builds the worker from them and from the handlers the adapters contribute (`AppDeps`):
//! a dispatcher built that way has a handler for every kind the application enqueues.

mod admin;
mod details;
pub mod dispatcher;
pub mod events;
mod webhooks;

#[cfg(test)]
pub(crate) mod fixture;

use std::sync::Arc;

use davhaven_domain::{AdminDecision, AdminOperation, RequestContext, decide_admin};
use davhaven_ports::OutboxHandler;

pub use admin::OutboxServiceImpl;
pub use dispatcher::OutboxDispatcher;
pub use events::DomainEventHandler;
pub use webhooks::WebhookServiceImpl;

use crate::error::{AppError, AppResult};
use crate::wiring::AppCore;

/// Checks the administration permission of the caller.
fn admin(ctx: &RequestContext, operation: AdminOperation) -> AppResult<()> {
    match decide_admin(&ctx.subject(), ctx.channel, operation) {
        AdminDecision::Allow => Ok(()),
        AdminDecision::Forbidden => Err(AppError::forbidden()),
    }
}

/// The outbox handlers this crate provides: `domain_event`, `imip` and `internal_delivery`: one for every kind of
/// record the application enqueues itself.
pub fn handlers(core: &AppCore) -> Vec<Arc<dyn OutboxHandler>> {
    vec![
        Arc::new(DomainEventHandler::new(core.clone())),
        Arc::new(crate::imip::ImipHandler::new(core.clone())),
        Arc::new(crate::itip::InternalDeliveryHandler::new(core.clone())),
    ]
}

/// Builds the dispatcher worker: the handlers the adapters contribute (`AppDeps::outbox_handlers`, for example
/// `webhook`), the handlers of this crate ([`handlers`]) and `extra` ones.
pub fn new_dispatcher(core: &AppCore, extra: impl IntoIterator<Item = Arc<dyn OutboxHandler>>) -> OutboxDispatcher {
    let mut all: Vec<Arc<dyn OutboxHandler>> = core.deps().outbox_handlers.clone();
    all.extend(handlers(core));
    all.extend(extra);
    OutboxDispatcher::new(core.clone(), all)
}
