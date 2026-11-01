//! The arguments of a tool call: parsing and the limits that belong to the MCP layer.
//!
//! The application services judge calendars, events and permissions; what the MCP layer judges is the shape of the
//! call itself. Those answers are the same for everybody and say nothing about any resource, so they come before
//! the services are asked:
//!
//! * the arguments are the JSON object the tool's input schema describes, and nothing else (unknown members are
//!   refused so that a misspelled `include_attendees` does not silently return redacted data);
//! * a time range has an end after its start and is at most `mcp.max_range_days` long;
//! * a `limit` defaults to the default page of the API limits and is capped at `mcp.max_results`, the cap that every
//!   list of the server obeys; like the API, a `limit` of zero is read as one;
//! * the text of a search has a length between [`MIN_QUERY_CHARS`] and [`MAX_QUERY_CHARS`];
//! * addresses are calendar user addresses, e-mail addresses without a scheme being `mailto:` addresses.
//!
//! Failures are `Invalid` errors that name the field (`/end`, `/query`, ...) so the assistant can correct the call.

use chrono::{DateTime, Duration, Utc};
use davhaven_app::services::TimeRange;
use davhaven_app::{AppError, SafeMessage};
use davhaven_domain::CalendarUserAddress;
use davhaven_wire::mcp::MAX_QUERY_CHARS;
use rmcp::model::JsonObject;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// How many slots `find_free_slots` returns when the call names no `limit`.
pub const DEFAULT_SLOTS: u32 = 20;

/// The most slots `find_free_slots` returns (PLAN 2.12, the schema says 50).
pub const MAX_SLOTS: u32 = 50;

/// The shortest text `search_events` looks for.
pub const MIN_QUERY_CHARS: usize = 2;

/// The longest comment of `respond_to_invitation`, in characters.
pub const MAX_COMMENT_CHARS: usize = 500;

/// The error for a field of the call that is wrong.
pub fn field_error(pointer: &'static str, code: &'static str, message: SafeMessage) -> AppError {
    AppError::invalid(message.clone()).with_field_error(pointer, code, message)
}

/// Reads the arguments of a call as the input type of the tool.
///
/// A missing `arguments` member is an empty object, which is what a tool without inputs is called with.
///
/// # Errors
///
/// `Invalid` when the arguments do not fit the input type: a required member is missing, a value has the wrong
/// type or an unknown member is present. The message names what serde found, which is about the client's own input.
pub fn parse<T: DeserializeOwned>(arguments: Option<JsonObject>) -> Result<T, AppError> {
    serde_json::from_value(Value::Object(arguments.unwrap_or_default())).map_err(|error| {
        // The pointer is relative to the arguments object: the whole object is wrong, so it is empty.
        field_error(
            "",
            "invalid",
            SafeMessage::sanitized(&format!("The arguments do not fit the tool: {error}")),
        )
    })
}

/// A time range of a tool call, checked against `mcp.max_range_days`.
///
/// # Errors
///
/// `Invalid` naming `/end` when the end is not after the start or the range is longer than `max_days`.
pub fn time_range(start: DateTime<Utc>, end: DateTime<Utc>, max_days: u32) -> Result<TimeRange, AppError> {
    if end <= start {
        return Err(field_error(
            "/end",
            "end-before-start",
            SafeMessage::from_static("The end of the range must be after its start."),
        ));
    }
    if end - start > Duration::days(i64::from(max_days)) {
        return Err(field_error(
            "/end",
            "range-too-long",
            SafeMessage::sanitized(&format!("The range is longer than {max_days} days.")),
        ));
    }
    Ok(TimeRange::new(Some(start), Some(end)))
}

/// The page size of a call: `requested`, or `default`, never above `cap`, and at least one (the API reads a limit
/// of zero as one, too).
pub fn page_size(requested: Option<u32>, default: u32, cap: u32) -> u32 {
    requested.unwrap_or(default).min(cap).max(1)
}

/// The text `search_events` looks for: the query without the white space around it.
///
/// # Errors
///
/// `Invalid` naming `/query` when the text has fewer than [`MIN_QUERY_CHARS`] or more than [`MAX_QUERY_CHARS`]
/// characters.
pub fn search_text(query: &str) -> Result<&str, AppError> {
    let query = query.trim();
    let length = query.chars().count();
    if length < MIN_QUERY_CHARS {
        return Err(field_error(
            "/query",
            "too-short",
            SafeMessage::sanitized(&format!("The search text needs at least {MIN_QUERY_CHARS} characters.")),
        ));
    }
    if length > MAX_QUERY_CHARS {
        return Err(field_error(
            "/query",
            "too-long",
            SafeMessage::sanitized(&format!("The search text is limited to {MAX_QUERY_CHARS} characters.")),
        ));
    }
    Ok(query)
}

/// The calendar user address of one entry of an `addresses` list.
///
/// An e-mail address without a scheme is read as a `mailto:` address; anything with a scheme must be a valid
/// calendar user address as it is.
///
/// # Errors
///
/// `Invalid` naming `/addresses` when the text is no address.
pub fn calendar_address(text: &str) -> Result<CalendarUserAddress, AppError> {
    let text = text.trim();
    let candidate = if text.contains(':') || !text.contains('@') {
        text.to_owned()
    } else {
        format!("mailto:{text}")
    };
    CalendarUserAddress::parse(&candidate).map_err(|_| {
        field_error(
            "/addresses",
            "invalid-address",
            SafeMessage::from_static("Every entry must be an e-mail address such as anna@example.org."),
        )
    })
}

/// The addresses of a call: at least one, each a valid address.
///
/// # Errors
///
/// `Invalid` naming `/addresses` for an empty list and for an entry that is no address.
pub fn calendar_addresses(texts: &[String]) -> Result<Vec<CalendarUserAddress>, AppError> {
    if texts.is_empty() {
        return Err(field_error(
            "/addresses",
            "empty",
            SafeMessage::from_static("Name at least one person."),
        ));
    }
    texts.iter().map(|text| calendar_address(text)).collect()
}

#[cfg(test)]
mod tests {
    use davhaven_domain::ErrorKind;
    use davhaven_wire::mcp::ListCalendarsInput;
    use serde_json::json;

    use super::*;

    fn at(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text).unwrap().with_timezone(&Utc)
    }

    fn object(value: &Value) -> Option<JsonObject> {
        value.as_object().cloned()
    }

    #[test]
    fn missing_arguments_are_an_empty_object() {
        assert_eq!(parse::<ListCalendarsInput>(None).unwrap(), ListCalendarsInput {});
        assert_eq!(
            parse::<ListCalendarsInput>(object(&json!({}))).unwrap(),
            ListCalendarsInput {}
        );
    }

    #[test]
    fn unknown_and_ill_typed_members_are_refused_as_a_whole() {
        let error = parse::<ListCalendarsInput>(object(&json!({"include_attendes": true}))).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Invalid);
        assert_eq!(error.field_errors().len(), 1);
        assert_eq!(
            error.field_errors()[0].pointer,
            "",
            "the pointer is relative to the arguments, and the whole object is wrong"
        );
        assert!(error.public_message().as_str().contains("include_attendes"), "{error}");
    }

    #[test]
    fn ranges_need_an_end_after_the_start_and_a_bounded_length() {
        let start = at("2027-03-01T00:00:00Z");
        let range = time_range(start, at("2027-03-08T00:00:00Z"), 92).unwrap();
        assert_eq!(range.start, Some(start));
        assert_eq!(range.end, Some(at("2027-03-08T00:00:00Z")));
        assert!(
            time_range(start, at("2027-06-01T00:00:00Z"), 92).is_ok(),
            "exactly 92 days is allowed"
        );
        for (end, code) in [
            (start, "end-before-start"),
            (at("2027-02-01T00:00:00Z"), "end-before-start"),
            (at("2027-06-01T00:00:01Z"), "range-too-long"),
            (at("2027-06-02T00:00:00Z"), "range-too-long"),
        ] {
            let error = time_range(start, end, 92).unwrap_err();
            assert_eq!(error.field_errors()[0].pointer, "/end");
            assert_eq!(error.field_errors()[0].code, code);
        }
        let error = time_range(start, at("2027-03-10T00:00:00Z"), 7).unwrap_err();
        assert_eq!(error.public_message().as_str(), "The range is longer than 7 days.");
    }

    #[test]
    fn limits_default_cap_and_never_reach_zero() {
        assert_eq!(page_size(None, 50, 200), 50);
        assert_eq!(page_size(Some(10), 50, 200), 10);
        assert_eq!(
            page_size(Some(5000), 50, 200),
            200,
            "the cap applies, the call is not refused"
        );
        assert_eq!(page_size(None, 50, 20), 20, "the cap applies to the default too");
        assert_eq!(
            page_size(Some(0), 50, 200),
            1,
            "a limit of zero is read as one, as the API does"
        );
    }

    #[test]
    fn the_text_of_a_search_has_a_length() {
        assert_eq!(search_text("  lunch ").unwrap(), "lunch");
        for short in ["", " ", "a", "  b  "] {
            let error = search_text(short).unwrap_err();
            assert_eq!(
                (error.field_errors()[0].pointer, error.field_errors()[0].code),
                ("/query", "too-short")
            );
        }
        assert!(search_text(&"x".repeat(MAX_QUERY_CHARS)).is_ok());
        let error = search_text(&"x".repeat(MAX_QUERY_CHARS + 1)).unwrap_err();
        assert_eq!(
            (error.field_errors()[0].pointer, error.field_errors()[0].code),
            ("/query", "too-long")
        );
        assert!(
            search_text(&"ä".repeat(MAX_QUERY_CHARS)).is_ok(),
            "the limit counts characters, not bytes"
        );
    }

    #[test]
    fn e_mail_addresses_become_mailto_addresses() {
        assert_eq!(
            calendar_address("Anna@Acme.example").unwrap().as_str(),
            "mailto:anna@acme.example"
        );
        assert_eq!(
            calendar_address("mailto:ben@acme.example").unwrap().as_str(),
            "mailto:ben@acme.example"
        );
        assert_eq!(
            calendar_address("  ben@acme.example ").unwrap().as_str(),
            "mailto:ben@acme.example"
        );
        for bad in ["", "not an address", "anna", "mailto:", "a@b@c"] {
            let error = calendar_address(bad).unwrap_err();
            assert_eq!(error.field_errors()[0].pointer, "/addresses", "{bad:?}");
        }
    }

    #[test]
    fn a_list_of_addresses_is_never_empty() {
        let error = calendar_addresses(&[]).unwrap_err();
        assert_eq!(error.field_errors()[0].code, "empty");
        let parsed = calendar_addresses(&["anna@acme.example".to_owned(), "ben@acme.example".to_owned()]).unwrap();
        assert_eq!(parsed.len(), 2);
        assert!(calendar_addresses(&["anna@acme.example".to_owned(), "nope".to_owned()]).is_err());
    }
}
