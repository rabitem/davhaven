//! Changes feed responses.
//!
//! `GET …/calendars/{calendar}/changes?since=` lists what changed in a calendar since a sync token (the same token
//! WebDAV sync uses). Foreign, garbled, future and pruned tokens answer 410 `sync-token-expired`; the client then
//! lists the calendar from scratch and keeps the new token.

use davhaven_domain::{ETag, ExternalKey, ObjectUri, SyncToken, Uid};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// What happened to an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// The object was created or changed.
    Upsert,
    /// The object was deleted.
    Delete,
}

/// One change of a calendar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct ChangeView {
    /// Whether the object exists after the change.
    pub kind: ChangeKind,
    /// The resource name of the object.
    #[schema(value_type = String)]
    pub uri: ObjectUri,
    /// The iCalendar UID, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub uid: Option<Uid>,
    /// The caller-chosen key, when the object has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub external_key: Option<ExternalKey>,
    /// The current entity tag; absent for deletions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub etag: Option<ETag>,
}

/// The response of the changes feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct ChangesResponse {
    /// The token to continue from.
    #[schema(value_type = String)]
    pub sync_token: SyncToken,
    /// The changes since the requested token, oldest first, one entry per object (the latest change wins).
    pub changes: Vec<ChangeView>,
    /// Whether more changes exist than this response lists; continue with `sync_token`.
    pub truncated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deletions_carry_no_etag() {
        let change = ChangeView {
            kind: ChangeKind::Delete,
            uri: ObjectUri::parse("gone.ics").unwrap(),
            uid: None,
            external_key: None,
            etag: None,
        };
        let json = serde_json::to_value(&change).unwrap();
        assert_eq!(json, serde_json::json!({"kind": "delete", "uri": "gone.ics"}));
        assert_eq!(serde_json::from_value::<ChangeView>(json).unwrap(), change);
    }
}
