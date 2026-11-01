//! Types shared by the service traits: pagination, conditional writes, merge patches and rendered pages.

use davhaven_wire::Cursor;
use serde_json::{Map, Value};

use crate::error::{AppError, AppResult, SafeMessage};

/// The pagination request of a listing: `?limit` and `?cursor` of the API, `limit` and `cursor` of MCP tools.
///
/// The service clamps `limit` to the API limits (default 50, maximum 200) and verifies the cursor's signature;
/// a forged, foreign or expired cursor is an `Invalid` error.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PageRequest {
    /// The requested page size; the default of the API limits when absent.
    pub limit: Option<u32>,
    /// The cursor of the previous page; the first page when absent.
    pub cursor: Option<Cursor>,
}

impl PageRequest {
    /// The first page with the default size.
    pub const fn first() -> Self {
        Self {
            limit: None,
            cursor: None,
        }
    }

    /// The first page with an explicit size.
    pub const fn with_limit(limit: u32) -> Self {
        Self {
            limit: Some(limit),
            cursor: None,
        }
    }

    /// The page after `cursor`, with the same size.
    #[must_use]
    pub fn after(self, cursor: Cursor) -> Self {
        Self {
            limit: self.limit,
            cursor: Some(cursor),
        }
    }
}

/// The conditional-request headers of a management API write (`If-Match`, `If-None-Match: *`).
///
/// Versions are the `version` counters of mutable resources (see `davhaven_wire::etag_for_version`). Calendar
/// objects use content ETags and have their own precondition type in the object service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Conditions {
    /// `If-Match`: the write applies only when the stored version is this one.
    pub if_match: Option<i64>,
    /// `If-None-Match: *`: the write applies only when the resource does not exist yet.
    pub if_none_match_any: bool,
}

impl Conditions {
    /// No conditions.
    pub const fn none() -> Self {
        Self {
            if_match: None,
            if_none_match_any: false,
        }
    }

    /// `If-Match: "v{version}"`.
    pub const fn if_match(version: i64) -> Self {
        Self {
            if_match: Some(version),
            if_none_match_any: false,
        }
    }

    /// `If-None-Match: *`.
    pub const fn create_only() -> Self {
        Self {
            if_match: None,
            if_none_match_any: true,
        }
    }

    /// Evaluates the conditions against the stored version (`None` when the resource does not exist).
    ///
    /// # Errors
    ///
    /// `PreconditionFailed` when `If-None-Match: *` meets an existing resource, or when `If-Match` names another
    /// version than the stored one (or the resource does not exist).
    pub fn check(&self, current: Option<i64>) -> AppResult<()> {
        if self.if_none_match_any && current.is_some() {
            return Err(AppError::precondition_failed());
        }
        if let Some(expected) = self.if_match
            && current != Some(expected)
        {
            return Err(AppError::precondition_failed());
        }
        Ok(())
    }

    /// The version of `If-Match` for operations that require it (deleting calendars and principals).
    ///
    /// # Errors
    ///
    /// `PreconditionRequired` (428) when there is no `If-Match`.
    pub fn require_if_match(&self) -> AppResult<i64> {
        self.if_match.ok_or_else(AppError::precondition_required)
    }
}

/// A JSON Merge Patch (RFC 7396) document for a `PATCH` request.
///
/// `null` removes a member, objects merge recursively and every other value replaces. The patch is applied to the
/// JSON form of the current resource and the result is validated like a `PUT` body.
#[derive(Debug, Clone, PartialEq)]
pub struct MergePatch(Value);

impl MergePatch {
    /// Wraps a patch document.
    ///
    /// # Errors
    ///
    /// `Invalid` unless the document is a JSON object (patches of resources are always objects).
    pub fn new(document: Value) -> AppResult<Self> {
        if document.is_object() {
            Ok(Self(document))
        } else {
            Err(AppError::invalid(SafeMessage::from_static(
                "A merge patch must be a JSON object.",
            )))
        }
    }

    /// The patch document.
    pub const fn document(&self) -> &Value {
        &self.0
    }

    /// Applies the patch to `target`.
    pub fn apply(&self, target: &mut Value) {
        merge(target, &self.0);
    }
}

fn merge(target: &mut Value, patch: &Value) {
    let Value::Object(patch_members) = patch else {
        *target = patch.clone();
        return;
    };
    if !target.is_object() {
        *target = Value::Object(Map::new());
    }
    if let Value::Object(members) = target {
        for (key, value) in patch_members {
            if value.is_null() {
                members.remove(key);
            } else {
                merge(members.entry(key.clone()).or_insert(Value::Null), value);
            }
        }
    }
}

/// The result of a create-or-replace: the stored resource and whether this call created it (201 or 200).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upserted<T> {
    /// The stored resource.
    pub value: T,
    /// Whether the resource did not exist before.
    pub created: bool,
}

impl<T> Upserted<T> {
    /// A resource that was just created.
    pub const fn created(value: T) -> Self {
        Self { value, created: true }
    }

    /// A resource that existed and was replaced or left unchanged.
    pub const fn replaced(value: T) -> Self {
        Self { value, created: false }
    }
}

/// An HTML page rendered by the application (RSVP pages, OAuth callback result). The web crate adds the security
/// headers; the page contains no third-party assets and works without JavaScript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedPage {
    /// The HTML document.
    pub html: String,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn page_requests_build_up() {
        assert_eq!(PageRequest::first(), PageRequest::default());
        let page = PageRequest::with_limit(10).after(Cursor::parse("abc").unwrap());
        assert_eq!(page.limit, Some(10));
        assert_eq!(page.cursor.unwrap().as_str(), "abc");
    }

    #[test]
    fn conditions_follow_http_semantics() {
        assert!(Conditions::none().check(None).is_ok());
        assert!(Conditions::none().check(Some(3)).is_ok());
        assert!(Conditions::create_only().check(None).is_ok());
        assert!(Conditions::create_only().check(Some(1)).is_err());
        assert!(Conditions::if_match(3).check(Some(3)).is_ok());
        for current in [Some(2), Some(4), None] {
            let error = Conditions::if_match(3).check(current).unwrap_err();
            assert_eq!(error.kind(), davhaven_domain::ErrorKind::PreconditionFailed);
        }
        assert_eq!(Conditions::if_match(3).require_if_match().unwrap(), 3);
        assert_eq!(
            Conditions::none().require_if_match().unwrap_err().kind(),
            davhaven_domain::ErrorKind::PreconditionRequired
        );
    }

    #[test]
    fn merge_patches_follow_rfc_7396() {
        let mut target = json!({"a": "b", "c": {"d": "e", "f": "g"}, "list": [1, 2]});
        let patch = MergePatch::new(json!({"a": "z", "c": {"f": null}, "list": [3], "new": {"x": 1}})).unwrap();
        patch.apply(&mut target);
        assert_eq!(target, json!({"a": "z", "c": {"d": "e"}, "list": [3], "new": {"x": 1}}));
        let mut scalar = json!("text");
        MergePatch::new(json!({"k": 1})).unwrap().apply(&mut scalar);
        assert_eq!(scalar, json!({"k": 1}));
        let mut removal = json!({"only": 1});
        MergePatch::new(json!({"only": null, "absent": null}))
            .unwrap()
            .apply(&mut removal);
        assert_eq!(removal, json!({}));
        assert!(MergePatch::new(json!([1])).is_err());
        assert!(MergePatch::new(json!(null)).is_err());
    }

    #[test]
    fn upserts_record_creation() {
        assert!(Upserted::created(1).created);
        assert!(!Upserted::replaced(1).created);
    }
}
