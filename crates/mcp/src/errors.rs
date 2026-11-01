//! Mapping of application errors to MCP tool results.
//!
//! A failed tool call is a **tool result** with `isError: true`, so the assistant can read the failure and react
//! (PLAN 2.12). JSON-RPC errors are reserved for protocol faults (unknown method, malformed request, unknown tool). The
//! translation is the same as everywhere else, in two steps:
//!
//! 1. `AppError::problem_details` (the one translation, shared with the edge layers) picks the catalog row from the
//!    error's precondition or kind and keeps the client-safe message and the invalid fields only; internal text never
//!    reaches the assistant;
//! 2. [`retryable`] is this crate's table from row to the MCP form: whether the assistant may repeat the same call
//!    later. It is an exhaustive `match`, and the tests compare it with the catalog.
//!
//! The result carries a short text (the title, the detail and one line per invalid field), and `_meta` with the
//! `ProblemDetails` document (the same document the management API returns, [`PROBLEM_META_KEY`]), the retry hint
//! ([`RETRYABLE_KEY`]) and, for rate limits, how long to wait ([`RETRY_AFTER_KEY`]).
//!
//! **A failed result has no `structuredContent`**, whatever the plan says (ADR-0014): every tool announces an
//! `outputSchema`, and the specification requires structured content to conform to it. A client that validates
//! `structuredContent` whenever it is present would turn every failure into an exception of its own and the assistant
//! would never see the failure or the hint. The problem document is not a result, so it travels in `_meta`.

use davhaven_app::AppError;
use davhaven_domain::RequestId;
use davhaven_http::rate_limit::retry_after_seconds;
use davhaven_wire::mcp::PROBLEM_META_KEY;
use davhaven_wire::{ProblemCode, ProblemDetails};
use rmcp::model::{CallToolResult, ContentBlock, MetaObject};
use serde_json::{Map, Value};

/// The vendor key of the retry hint in the `_meta` of a failed tool result.
pub const RETRYABLE_KEY: &str = "davhaven/retryable";

/// The vendor key of the wait, in whole seconds, in the `_meta` of a rate-limited tool result.
pub const RETRY_AFTER_KEY: &str = "davhaven/retry_after_seconds";

/// Whether an assistant may repeat the same tool call later: rate limits, overload and requests that are still
/// being processed. Everything else needs a different call.
pub const fn retryable(code: ProblemCode) -> bool {
    match code {
        ProblemCode::RateLimited | ProblemCode::Unavailable | ProblemCode::IdempotencyInProgress => true,
        ProblemCode::BadRequest
        | ProblemCode::Unauthenticated
        | ProblemCode::Forbidden
        | ProblemCode::NotFound
        | ProblemCode::MethodNotAllowed
        | ProblemCode::Conflict
        | ProblemCode::PreconditionFailed
        | ProblemCode::PreconditionRequired
        | ProblemCode::PayloadTooLarge
        | ProblemCode::UnsupportedMediaType
        | ProblemCode::ValidationFailed
        | ProblemCode::Internal
        | ProblemCode::NotImplemented
        | ProblemCode::IdempotencyKeyReuse
        | ProblemCode::SecretNotReplayable
        | ProblemCode::FeatureNotEnabled
        | ProblemCode::NameReserved
        | ProblemCode::ExternalRefReserved
        | ProblemCode::AddressReserved
        | ProblemCode::InvalidCalendarData
        | ProblemCode::InvalidCalendarObject
        | ProblemCode::UnsupportedCalendarComponent
        | ProblemCode::UnsupportedCalendarData
        | ProblemCode::UidConflict
        | ProblemCode::ResourceTooLarge
        | ProblemCode::DateTooEarly
        | ProblemCode::DateTooLate
        | ProblemCode::TooManyInstances
        | ProblemCode::TooManyAttendees
        | ProblemCode::SchedulingUidConflict
        | ProblemCode::OrganizerMismatch
        | ProblemCode::OrganizerNotAllowed
        | ProblemCode::OrganizerChangeNotAllowed
        | ProblemCode::AttendeeChangeNotAllowed
        | ProblemCode::InvalidSchedulingMessage
        | ProblemCode::SyncTokenExpired
        | ProblemCode::TooManyMatches
        | ProblemCode::DepthInfinityRefused
        | ProblemCode::InvalidFilter
        | ProblemCode::ResourceExists
        | ProblemCode::ProtectedProperty
        | ProblemCode::SharingNotAllowed
        | ProblemCode::InvalidSharee
        | ProblemCode::UnsupportedReport
        | ProblemCode::TooManyHrefs
        | ProblemCode::SyncTraversalUnsupported
        | ProblemCode::ForeignDestination => false,
    }
}

/// The problem document of an application error, as the management API would return it.
pub fn problem_details(error: &AppError, request_id: RequestId) -> ProblemDetails {
    error.problem_details().with_request_id(request_id)
}

/// The short text of a failed result: the title, the detail, and one line per invalid field.
fn summary(details: &ProblemDetails) -> String {
    let head = match &details.detail {
        Some(detail) => format!("{}: {detail}", details.title),
        None => details.title.clone(),
    };
    let fields = details
        .errors
        .iter()
        .map(|field| format!("{}: {}", field.pointer, field.message));
    std::iter::once(head).chain(fields).collect::<Vec<_>>().join("\n")
}

/// The `CallToolResult` of a failed tool call: `isError: true`, a text and, in `_meta`, the problem and the retry hint.
/// It has no `structuredContent` (see the module documentation).
pub fn tool_error(error: &AppError, request_id: RequestId) -> CallToolResult {
    let details = problem_details(error, request_id);
    let mut meta = Map::new();
    meta.insert(RETRYABLE_KEY.to_owned(), Value::Bool(retryable(details.code)));
    if let Some(wait) = error.retry_after() {
        meta.insert(RETRY_AFTER_KEY.to_owned(), Value::from(retry_after_seconds(wait)));
    }
    meta.insert(
        PROBLEM_META_KEY.to_owned(),
        serde_json::to_value(&details).unwrap_or(Value::Null),
    );
    let mut result = CallToolResult::error(vec![ContentBlock::text(summary(&details))]);
    result.meta = Some(MetaObject(meta));
    result
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use davhaven_app::SafeMessage;
    use davhaven_domain::{ErrorKind, Href, Precondition};

    use super::*;

    fn request_id() -> RequestId {
        RequestId::parse("018f3c1e-7b2a-7c3d-9e4f-0123456789ab").unwrap()
    }

    fn json_of(error: &AppError) -> Value {
        serde_json::to_value(tool_error(error, request_id())).unwrap()
    }

    #[test]
    fn the_table_agrees_with_the_catalog_for_every_row() {
        for code in ProblemCode::ALL {
            assert_eq!(retryable(*code), code.retryable(), "{}", code.code());
        }
    }

    #[test]
    fn exactly_the_transient_rows_are_retryable() {
        let retryable_rows: Vec<&str> = ProblemCode::ALL
            .iter()
            .filter(|code| retryable(**code))
            .map(|code| code.code())
            .collect();
        assert_eq!(
            retryable_rows,
            vec!["rate-limited", "unavailable", "idempotency-in-progress"]
        );
    }

    #[test]
    fn failures_are_tool_results_with_the_problem_in_the_meta_and_no_structured_content() {
        let error = AppError::new(ErrorKind::Invalid)
            .with_public_message(SafeMessage::from_static("The range is longer than 92 days."));
        let result = json_of(&error);
        assert_eq!(result["isError"], true);
        assert_eq!(result["content"][0]["type"], "text");
        assert_eq!(
            result["content"][0]["text"],
            "Validation failed: The range is longer than 92 days."
        );
        let problem = &result["_meta"][PROBLEM_META_KEY];
        assert_eq!(problem["type"], "urn:davhaven:problem:validation-failed");
        assert_eq!(problem["code"], "validation-failed");
        assert_eq!(problem["detail"], "The range is longer than 92 days.");
        assert_eq!(problem["request_id"], "018f3c1e-7b2a-7c3d-9e4f-0123456789ab");
        assert_eq!(result["_meta"][RETRYABLE_KEY], false);
        assert!(result["_meta"].get(RETRY_AFTER_KEY).is_none());
        assert!(
            result.get("structuredContent").is_none(),
            "a failure is no result: a client that validates structured content against the output schema would reject it: {result}"
        );
    }

    #[test]
    fn invalid_fields_are_listed_in_the_document_and_in_the_text() {
        let error = AppError::new(ErrorKind::Invalid)
            .with_field_error(
                "/end",
                "range-too-long",
                SafeMessage::from_static("The range is too long."),
            )
            .with_field_error("/limit", "out-of-range", SafeMessage::from_static("Too many."));
        let result = json_of(&error);
        let fields = result["_meta"][PROBLEM_META_KEY]["errors"].as_array().unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0]["pointer"], "/end");
        assert_eq!(fields[0]["code"], "range-too-long");
        assert_eq!(
            result["content"][0]["text"],
            "Validation failed\n/end: The range is too long.\n/limit: Too many."
        );
    }

    #[test]
    fn rate_limits_tell_the_assistant_it_may_try_again_and_when() {
        let result = json_of(&AppError::rate_limited(Duration::from_millis(29_500)));
        assert_eq!(result["_meta"][PROBLEM_META_KEY]["code"], "rate-limited");
        assert_eq!(result["_meta"][RETRYABLE_KEY], true);
        assert_eq!(result["_meta"][RETRY_AFTER_KEY], 30);
        assert_eq!(result["content"][0]["text"], "Too many requests");
    }

    #[test]
    fn preconditions_pick_their_row_and_internal_text_stays_out() {
        let href = Href::parse("/dav/calendars/acme/anna/work/x.ics").unwrap();
        let conflict = AppError::conflict().with_precondition(Precondition::NoUidConflict(href));
        let result = json_of(&conflict);
        assert_eq!(result["_meta"][PROBLEM_META_KEY]["code"], "uid-conflict");
        assert!(
            !result.to_string().contains("/dav/"),
            "no href of a resource leaks: {result}"
        );

        let secret = "relation \"calendar_objects\" does not exist (password=hunter2)";
        let internal = json_of(&AppError::internal(std::io::Error::other(secret)));
        assert_eq!(internal["_meta"][PROBLEM_META_KEY]["code"], "internal");
        assert!(!internal.to_string().contains("hunter2"), "{internal}");
    }

    #[test]
    fn unsupported_operations_are_not_implemented_and_not_retryable() {
        let result = json_of(&AppError::new(ErrorKind::Unsupported));
        assert_eq!(result["_meta"][PROBLEM_META_KEY]["code"], "not-implemented");
        assert_eq!(result["_meta"][RETRYABLE_KEY], false);
    }
}
