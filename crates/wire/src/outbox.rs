//! Outbox item views.
//!
//! The outbox holds work that must happen after a transaction commits: iMIP mail, internal delivery of large
//! scheduling messages, webhook deliveries and domain events. Operators inspect dead items (failed permanently or
//! out of attempts) and retry them. The payload is not exposed: it can reference mail recipients.

use chrono::{DateTime, Utc};
use davhaven_domain::OutboxId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The state of an outbox item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OutboxStatus {
    /// Waiting for its next attempt.
    Pending,
    /// Claimed by a dispatcher.
    InFlight,
    /// Handled successfully.
    Done,
    /// Failed permanently or exhausted its attempts; waits for an operator.
    Dead,
}

/// An outbox item as `GET …/outbox` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct OutboxItemView {
    /// The item id.
    #[schema(value_type = Uuid)]
    pub id: OutboxId,
    /// The message kind, for example `imip` or `webhook`.
    pub kind: String,
    /// The state of the item.
    pub status: OutboxStatus,
    /// How many times the item was claimed.
    pub attempts: u32,
    /// When the item is next due.
    pub next_attempt_at: DateTime<Utc>,
    /// The error of the last failed attempt, for operators.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// When the item was created.
    pub created_at: DateTime<Utc>,
    /// When the item was last changed.
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_use_the_store_spelling() {
        assert_eq!(serde_json::to_string(&OutboxStatus::InFlight).unwrap(), "\"in_flight\"");
        assert_eq!(
            serde_json::from_str::<OutboxStatus>("\"dead\"").unwrap(),
            OutboxStatus::Dead
        );
    }
}
