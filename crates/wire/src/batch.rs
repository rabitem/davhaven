//! Batch upsert requests and results for managed calendars.
//!
//! `POST …/calendars/{calendar}/objects/batch` writes up to 1000 objects in one transaction (PLAN 2.10): all or
//! nothing, keyed by the caller's `external_key`. The UID of an object is `UUIDv5(calendar_id, external_key)`
//! unless the event carries one. The server bumps `SEQUENCE`, emits one `calendar.objects_changed` event and
//! never schedules. A request with the same `Idempotency-Key` returns the stored result.

use davhaven_domain::{ApiLimits, ETag, ExternalKey, ObjectUri, SyncToken, Uid};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::event::EventView;
use crate::problem::ProblemDetails;

/// How a batch treats objects that are not mentioned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BatchMode {
    /// Only the listed objects and `deletes` are touched.
    #[default]
    Merge,
    /// Objects whose external key starts with `replace_scope_prefix` and that are not listed are deleted.
    Replace,
}

/// One object of a batch: exactly one of `event` and `ical`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchItem {
    /// The caller's stable key of the object (`[A-Za-z0-9._:~-]{1,200}`).
    #[schema(value_type = String)]
    pub external_key: ExternalKey,
    /// The event as JSON; merged into the stored component like a JSON Merge Patch (RFC 7396): absent fields keep
    /// their value, `null` removes a field, unknown properties and alarms are kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<EventView>,
    /// The event as iCalendar text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ical: Option<String>,
}

/// The body of a batch upsert.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchRequest {
    /// Whether unlisted objects are kept (`merge`, the default) or deleted within the scope (`replace`).
    #[serde(default)]
    pub mode: BatchMode,
    /// In `replace` mode: only objects whose external key starts with this prefix may be deleted. Required with
    /// `replace`, so one integration cannot wipe the objects of another.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replace_scope_prefix: Option<String>,
    /// Permits a batch without items and deletes in `replace` mode (it would delete the whole scope).
    #[serde(default)]
    pub allow_empty: bool,
    /// The most objects the batch may delete; a larger deletion fails the batch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_deletes: Option<u32>,
    /// The objects to create or update (at most 1000).
    #[serde(default)]
    pub items: Vec<BatchItem>,
    /// External keys to delete in `merge` mode.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<String>)]
    pub deletes: Vec<ExternalKey>,
}

/// Why a batch request is rejected before any object is looked at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchRequestError {
    /// A JSON Pointer to the offending member of the request.
    pub pointer: String,
    /// A client-safe explanation.
    pub message: &'static str,
}

impl core::fmt::Display for BatchRequestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.pointer, self.message)
    }
}

impl std::error::Error for BatchRequestError {}

impl BatchRequest {
    /// Checks the rules that depend only on the request itself and the API limits: at most
    /// `max_batch_items` items, exactly one of `event` and `ical` per item, unique external keys across `items`
    /// and `deletes`, a scope prefix with `replace`, and no empty batch unless `allow_empty` is set.
    ///
    /// # Errors
    ///
    /// Returns the first violated rule with the JSON Pointer of the offending member.
    pub fn validate(&self, limits: &ApiLimits) -> Result<(), BatchRequestError> {
        let error = |pointer: String, message: &'static str| BatchRequestError { pointer, message };
        let max_items = usize::try_from(limits.max_batch_items).unwrap_or(usize::MAX);
        if self.items.len().saturating_add(self.deletes.len()) > max_items {
            return Err(error(String::new(), "the batch has more entries than the limit allows"));
        }
        let mut seen = std::collections::HashSet::new();
        for (index, item) in self.items.iter().enumerate() {
            let pointer = format!("/items/{index}");
            if item.event.is_some() == item.ical.is_some() {
                return Err(error(pointer, "exactly one of event and ical is required"));
            }
            if !seen.insert(&item.external_key) {
                return Err(error(pointer, "the external key appears more than once"));
            }
        }
        for (index, key) in self.deletes.iter().enumerate() {
            if !seen.insert(key) {
                return Err(error(
                    format!("/deletes/{index}"),
                    "the external key appears more than once",
                ));
            }
        }
        match (self.mode, &self.replace_scope_prefix) {
            (BatchMode::Replace, None) => {
                return Err(error(
                    "/replace_scope_prefix".to_owned(),
                    "replace mode needs a scope prefix",
                ));
            }
            (BatchMode::Replace, Some(prefix)) if prefix.is_empty() => {
                return Err(error(
                    "/replace_scope_prefix".to_owned(),
                    "the scope prefix must not be empty",
                ));
            }
            (BatchMode::Merge, Some(_)) => {
                return Err(error(
                    "/replace_scope_prefix".to_owned(),
                    "a scope prefix only applies to replace mode",
                ));
            }
            _ => {}
        }
        if self.items.is_empty() && self.deletes.is_empty() && !self.allow_empty {
            return Err(error(String::new(), "an empty batch needs allow_empty"));
        }
        Ok(())
    }
}

/// What happened to one object of a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BatchOutcome {
    /// The object did not exist and was created.
    Created,
    /// The object existed and its content changed.
    Updated,
    /// The content hash is unchanged: nothing was written, the ETag and sync token stay.
    Unchanged,
    /// The object was deleted.
    Deleted,
    /// The object could not be written; `problem` says why (the batch as a whole then fails with 422).
    Failed,
}

/// The result for one external key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct BatchItemResult {
    /// The external key of the request entry.
    #[schema(value_type = String)]
    pub external_key: ExternalKey,
    /// What happened.
    pub outcome: BatchOutcome,
    /// The iCalendar UID of the object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub uid: Option<Uid>,
    /// The resource name of the object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub uri: Option<ObjectUri>,
    /// The entity tag after the batch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub etag: Option<ETag>,
    /// Why the entry failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<ProblemDetails>,
}

/// The result of a batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct BatchResult {
    /// The sync token of the calendar after the batch; unchanged when the batch failed.
    #[schema(value_type = String)]
    pub sync_token: SyncToken,
    /// One result per request entry: `items` in order, then `deletes`, then keys deleted by `replace`.
    pub results: Vec<BatchItemResult>,
}

impl BatchResult {
    /// Whether any entry failed. Batches are all or nothing: with a failure nothing was written and the API
    /// answers 422 with this result as the body.
    pub fn has_failures(&self) -> bool {
        self.results.iter().any(|result| result.outcome == BatchOutcome::Failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(text: &str) -> ExternalKey {
        ExternalKey::parse(text).unwrap()
    }

    fn event_item(external_key: &str) -> BatchItem {
        BatchItem {
            external_key: key(external_key),
            event: Some(EventView::default()),
            ical: None,
        }
    }

    fn limits() -> ApiLimits {
        ApiLimits::default()
    }

    #[test]
    fn requests_deserialize_with_defaults() {
        let request: BatchRequest =
            serde_json::from_str(r#"{"items": [{"external_key": "a", "ical": "BEGIN:VCALENDAR"}], "deletes": ["b"]}"#)
                .unwrap();
        assert_eq!(request.mode, BatchMode::Merge);
        assert!(!request.allow_empty);
        assert_eq!(request.deletes, vec![key("b")]);
        assert!(serde_json::from_str::<BatchRequest>(r#"{"itemz": []}"#).is_err());
        request.validate(&limits()).unwrap();
    }

    #[test]
    fn items_need_exactly_one_representation() {
        let mut both = event_item("a");
        both.ical = Some("BEGIN:VCALENDAR".to_owned());
        let neither = BatchItem {
            external_key: key("b"),
            event: None,
            ical: None,
        };
        for item in [both, neither] {
            let request = BatchRequest {
                items: vec![item],
                ..BatchRequest::default()
            };
            let error = request.validate(&limits()).unwrap_err();
            assert_eq!(error.pointer, "/items/0");
            assert_eq!(error.to_string(), "/items/0: exactly one of event and ical is required");
        }
    }

    #[test]
    fn keys_must_be_unique_across_items_and_deletes() {
        let request = BatchRequest {
            items: vec![event_item("a"), event_item("a")],
            ..BatchRequest::default()
        };
        assert_eq!(request.validate(&limits()).unwrap_err().pointer, "/items/1");
        let request = BatchRequest {
            items: vec![event_item("a")],
            deletes: vec![key("a")],
            ..BatchRequest::default()
        };
        assert_eq!(request.validate(&limits()).unwrap_err().pointer, "/deletes/0");
    }

    #[test]
    fn replace_needs_a_scope_and_merge_must_not_have_one() {
        let replace = BatchRequest {
            mode: BatchMode::Replace,
            items: vec![event_item("shop:1")],
            ..BatchRequest::default()
        };
        assert_eq!(
            replace.validate(&limits()).unwrap_err().pointer,
            "/replace_scope_prefix"
        );
        let scoped = BatchRequest {
            replace_scope_prefix: Some("shop:".to_owned()),
            ..replace.clone()
        };
        scoped.validate(&limits()).unwrap();
        let empty_prefix = BatchRequest {
            replace_scope_prefix: Some(String::new()),
            ..replace
        };
        assert_eq!(
            empty_prefix.validate(&limits()),
            Err(BatchRequestError {
                pointer: "/replace_scope_prefix".to_owned(),
                message: "the scope prefix must not be empty",
            })
        );
        let merge_with_scope = BatchRequest {
            replace_scope_prefix: Some("shop:".to_owned()),
            items: vec![event_item("shop:1")],
            ..BatchRequest::default()
        };
        assert_eq!(
            merge_with_scope.validate(&limits()),
            Err(BatchRequestError {
                pointer: "/replace_scope_prefix".to_owned(),
                message: "a scope prefix only applies to replace mode",
            })
        );
    }

    #[test]
    fn empty_batches_and_oversized_batches_are_rejected() {
        let empty = BatchRequest::default();
        let error = empty.validate(&limits()).unwrap_err();
        assert_eq!(error.message, "an empty batch needs allow_empty");
        assert_eq!(error.to_string(), ": an empty batch needs allow_empty");
        // A batch of deletes only is not empty.
        let deletes_only = BatchRequest {
            deletes: vec![key("gone")],
            ..BatchRequest::default()
        };
        deletes_only.validate(&limits()).unwrap();
        let allowed = BatchRequest {
            allow_empty: true,
            ..BatchRequest::default()
        };
        allowed.validate(&limits()).unwrap();
        let small = ApiLimits {
            max_batch_items: 2,
            ..ApiLimits::default()
        };
        let too_many = BatchRequest {
            items: vec![event_item("a"), event_item("b")],
            deletes: vec![key("c")],
            ..BatchRequest::default()
        };
        assert_eq!(too_many.validate(&small).unwrap_err().pointer, "");
        let fits = BatchRequest {
            items: vec![event_item("a"), event_item("b")],
            ..BatchRequest::default()
        };
        fits.validate(&small).unwrap();
    }

    #[test]
    fn outcomes_use_snake_case() {
        assert_eq!(
            serde_json::to_string(&BatchOutcome::Unchanged).unwrap(),
            "\"unchanged\""
        );
        assert_eq!(serde_json::to_string(&BatchMode::Replace).unwrap(), "\"replace\"");
    }
}
