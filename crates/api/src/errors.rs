//! Mapping of application errors to RFC 9457 problem responses.
//!
//! Every failure of the management API is a [`ProblemCode`] row rendered as `application/problem+json`
//! (PLAN 2.10, F0.4): `type = urn:davhaven:problem:{code}`, `title`, `status`, `code`, `request_id` and, for
//! validation problems, `errors[{pointer, code, message}]`. The translation happens exactly once, in two steps:
//!
//! 1. [`EdgeProblem::from_app_error`](davhaven_http::EdgeProblem::from_app_error), which builds on
//!    `AppError::problem_details`, picks the row from the error's precondition or kind
//!    ([`ProblemCode::from_error`]) and keeps only the client-safe message; the source error and every internal text
//!    stay in the logs;
//! 2. [`api_status`] is this crate's table from row to HTTP status. It is an exhaustive `match`, so a new row in the
//!    catalog does not compile until the API says what it answers, and the tests compare the table with the
//!    catalog and with an independent list.
//!
//! The `unsupported` stubs of services that are not implemented yet are the `not-implemented` row: 501.

use davhaven_http::JsonProblems;
use davhaven_wire::ProblemCode;

/// The HTTP status of the management API for a problem row.
///
/// Rows that only DAV clients see (`depth-infinity-refused`, `too-many-matches`, ...) are still answered
/// sensibly when an API call runs into them.
pub const fn api_status(code: ProblemCode) -> u16 {
    match code {
        ProblemCode::BadRequest | ProblemCode::DepthInfinityRefused | ProblemCode::UnsupportedReport => 400,
        ProblemCode::Unauthenticated => 401,
        ProblemCode::Forbidden
        | ProblemCode::OrganizerNotAllowed
        | ProblemCode::OrganizerChangeNotAllowed
        | ProblemCode::AttendeeChangeNotAllowed
        | ProblemCode::ProtectedProperty
        | ProblemCode::SharingNotAllowed => 403,
        ProblemCode::NotFound => 404,
        ProblemCode::MethodNotAllowed => 405,
        ProblemCode::Conflict
        | ProblemCode::IdempotencyInProgress
        | ProblemCode::SecretNotReplayable
        | ProblemCode::FeatureNotEnabled
        | ProblemCode::NameReserved
        | ProblemCode::ExternalRefReserved
        | ProblemCode::AddressReserved
        | ProblemCode::UidConflict
        | ProblemCode::SchedulingUidConflict
        | ProblemCode::ResourceExists => 409,
        ProblemCode::SyncTokenExpired => 410,
        ProblemCode::PreconditionFailed => 412,
        ProblemCode::PayloadTooLarge | ProblemCode::ResourceTooLarge => 413,
        ProblemCode::UnsupportedMediaType | ProblemCode::UnsupportedCalendarData => 415,
        ProblemCode::ValidationFailed
        | ProblemCode::IdempotencyKeyReuse
        | ProblemCode::InvalidCalendarData
        | ProblemCode::InvalidCalendarObject
        | ProblemCode::UnsupportedCalendarComponent
        | ProblemCode::DateTooEarly
        | ProblemCode::DateTooLate
        | ProblemCode::TooManyInstances
        | ProblemCode::TooManyAttendees
        | ProblemCode::OrganizerMismatch
        | ProblemCode::InvalidSchedulingMessage
        | ProblemCode::TooManyMatches
        | ProblemCode::InvalidFilter
        | ProblemCode::InvalidSharee
        | ProblemCode::TooManyHrefs
        | ProblemCode::SyncTraversalUnsupported
        | ProblemCode::ForeignDestination => 422,
        ProblemCode::PreconditionRequired => 428,
        ProblemCode::RateLimited => 429,
        ProblemCode::Internal => 500,
        ProblemCode::NotImplemented => 501,
        ProblemCode::Unavailable => 503,
    }
}

/// The `WWW-Authenticate` challenge of 401 responses.
pub const CHALLENGE: &str = "Bearer realm=\"davhaven\"";

/// The renderer of the management API: RFC 9457 documents with [`api_status`] and the bearer challenge.
pub fn renderer() -> JsonProblems {
    JsonProblems::catalog()
        .with_status_table(api_status)
        .with_challenge(CHALLENGE)
}

#[cfg(test)]
mod tests {
    use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER, WWW_AUTHENTICATE};
    use davhaven_app::{AppError, SafeMessage};
    use davhaven_domain::{ErrorKind, Href, Precondition, Privilege, RequestId};
    use davhaven_http::EdgeProblem;
    use davhaven_http::problem::ProblemRenderer;
    use http_body_util::BodyExt as _;

    use super::*;

    /// The status of every row, written down independently of the table under test.
    const EXPECTED: [(&str, u16); 50] = [
        ("bad-request", 400),
        ("unauthenticated", 401),
        ("forbidden", 403),
        ("not-found", 404),
        ("method-not-allowed", 405),
        ("conflict", 409),
        ("precondition-failed", 412),
        ("precondition-required", 428),
        ("payload-too-large", 413),
        ("unsupported-media-type", 415),
        ("validation-failed", 422),
        ("rate-limited", 429),
        ("internal", 500),
        ("not-implemented", 501),
        ("unavailable", 503),
        ("idempotency-key-reuse", 422),
        ("idempotency-in-progress", 409),
        ("secret-not-replayable", 409),
        ("feature-not-enabled", 409),
        ("invalid-calendar-data", 422),
        ("invalid-calendar-object", 422),
        ("unsupported-calendar-component", 422),
        ("unsupported-calendar-data", 415),
        ("uid-conflict", 409),
        ("resource-too-large", 413),
        ("date-too-early", 422),
        ("date-too-late", 422),
        ("too-many-instances", 422),
        ("too-many-attendees", 422),
        ("scheduling-uid-conflict", 409),
        ("organizer-mismatch", 422),
        ("organizer-not-allowed", 403),
        ("organizer-change-not-allowed", 403),
        ("attendee-change-not-allowed", 403),
        ("invalid-scheduling-message", 422),
        ("sync-token-expired", 410),
        ("too-many-matches", 422),
        ("depth-infinity-refused", 400),
        ("invalid-filter", 422),
        ("resource-exists", 409),
        ("protected-property", 403),
        ("sharing-not-allowed", 403),
        ("invalid-sharee", 422),
        ("name-reserved", 409),
        ("external-ref-reserved", 409),
        ("address-reserved", 409),
        ("unsupported-report", 400),
        ("too-many-hrefs", 422),
        ("sync-traversal-unsupported", 422),
        ("foreign-destination", 422),
    ];

    #[test]
    fn the_table_covers_every_row_of_the_catalog_and_agrees_with_it() {
        assert_eq!(EXPECTED.len(), ProblemCode::ALL.len(), "a row was added to the catalog");
        for code in ProblemCode::ALL {
            let expected = EXPECTED
                .iter()
                .find(|(text, _)| *text == code.code())
                .unwrap_or_else(|| panic!("{} is missing from the expectations", code.code()));
            assert_eq!(api_status(*code), expected.1, "{}", code.code());
            assert_eq!(
                api_status(*code),
                code.http_status(),
                "{} differs from the catalog",
                code.code()
            );
        }
    }

    /// The row every error kind maps to when nothing refines it.
    const KINDS: [(ErrorKind, &str); 12] = [
        (ErrorKind::NotFound, "not-found"),
        (ErrorKind::Unauthenticated, "unauthenticated"),
        (ErrorKind::Forbidden, "forbidden"),
        (ErrorKind::Conflict, "conflict"),
        (ErrorKind::PreconditionFailed, "precondition-failed"),
        (ErrorKind::PreconditionRequired, "precondition-required"),
        (ErrorKind::Invalid, "validation-failed"),
        (ErrorKind::TooLarge, "payload-too-large"),
        (ErrorKind::RateLimited, "rate-limited"),
        (ErrorKind::Unavailable, "unavailable"),
        (ErrorKind::Unsupported, "not-implemented"),
        (ErrorKind::Internal, "internal"),
    ];

    #[test]
    fn every_error_kind_maps_to_its_row_and_status() {
        assert_eq!(KINDS.len(), ErrorKind::ALL.len());
        for (kind, code) in KINDS {
            let problem = EdgeProblem::from_app_error(&AppError::new(kind));
            assert_eq!(problem.code().code(), code, "{kind}");
            let status = EXPECTED.iter().find(|(text, _)| *text == code).unwrap().1;
            assert_eq!(api_status(problem.code()), status, "{kind}");
            assert_eq!(problem.detail(), None, "the generic text of {kind} is not a detail");
        }
    }

    #[test]
    fn every_precondition_maps_to_its_row() {
        let href = || Href::parse("/dav/calendars/acme/anna/work/x.ics").unwrap();
        let cases = [
            (Precondition::need_privilege(href(), Privilege::Read), "forbidden"),
            (
                Precondition::ValidCalendarData("bad".to_owned()),
                "invalid-calendar-data",
            ),
            (Precondition::ValidCalendarObjectResource, "invalid-calendar-object"),
            (
                Precondition::SupportedCalendarComponent,
                "unsupported-calendar-component",
            ),
            (Precondition::SupportedCalendarData, "unsupported-calendar-data"),
            (Precondition::NoUidConflict(href()), "uid-conflict"),
            (Precondition::MaxResourceSize, "resource-too-large"),
            (Precondition::MinDateTime, "date-too-early"),
            (Precondition::MaxDateTime, "date-too-late"),
            (Precondition::MaxInstances, "too-many-instances"),
            (Precondition::MaxAttendeesPerInstance, "too-many-attendees"),
            (
                Precondition::UniqueSchedulingObjectResource(href()),
                "scheduling-uid-conflict",
            ),
            (Precondition::SameOrganizerInAllComponents, "organizer-mismatch"),
            (Precondition::OrganizerAllowed, "organizer-not-allowed"),
            (
                Precondition::AllowedOrganizerSchedulingObjectChange,
                "organizer-change-not-allowed",
            ),
            (
                Precondition::AllowedAttendeeSchedulingObjectChange,
                "attendee-change-not-allowed",
            ),
            (Precondition::ValidSchedulingMessage, "invalid-scheduling-message"),
            (Precondition::ValidSyncToken, "sync-token-expired"),
            (Precondition::NumberOfMatchesWithinLimits, "too-many-matches"),
            (Precondition::PropfindFiniteDepth, "depth-infinity-refused"),
            (Precondition::ValidFilter, "invalid-filter"),
            (Precondition::ResourceMustBeNull, "resource-exists"),
            (Precondition::CannotModifyProtectedProperty, "protected-property"),
            (Precondition::SharingNotAllowed, "sharing-not-allowed"),
            (Precondition::InvalidSharee(href()), "invalid-sharee"),
            (Precondition::FeatureNotEnabled, "feature-not-enabled"),
            (Precondition::NameReserved, "name-reserved"),
            (Precondition::ExternalRefReserved, "external-ref-reserved"),
            (Precondition::AddressReserved, "address-reserved"),
        ];
        assert_eq!(
            cases.len(),
            29,
            "the plan lists 25 preconditions and the catalog adds feature-not-enabled and the three reservations"
        );
        for (precondition, code) in cases {
            let name = precondition.code();
            let error = AppError::new(ErrorKind::Invalid).with_precondition(precondition);
            assert_eq!(EdgeProblem::from_app_error(&error).code().code(), code, "{name}");
        }
    }

    async fn render(problem: EdgeProblem) -> (axum::response::Response, serde_json::Value) {
        let request_id = RequestId::parse("018f3c1e-7b2a-7c3d-9e4f-0123456789ab").unwrap();
        let mut response = renderer().render(&problem, Some(request_id));
        let body = std::mem::take(response.body_mut());
        let bytes = body.collect().await.unwrap().to_bytes();
        (response, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test]
    async fn every_row_renders_as_a_problem_document_with_its_status() {
        for code in ProblemCode::ALL {
            let (response, json) = render(EdgeProblem::new(*code)).await;
            assert_eq!(response.status().as_u16(), api_status(*code), "{}", code.code());
            assert_eq!(response.headers()[CONTENT_TYPE], "application/problem+json");
            assert_eq!(response.headers()[CACHE_CONTROL], "no-store", "{}", code.code());
            assert_eq!(json["type"], format!("urn:davhaven:problem:{}", code.code()));
            assert_eq!(json["code"], code.code());
            assert_eq!(json["status"], api_status(*code));
            assert_eq!(json["title"], code.title());
            assert_eq!(json["request_id"], "018f3c1e-7b2a-7c3d-9e4f-0123456789ab");
            assert_eq!(
                response.headers().contains_key(WWW_AUTHENTICATE),
                *code == ProblemCode::Unauthenticated,
                "{}",
                code.code()
            );
            if *code == ProblemCode::Unauthenticated {
                assert_eq!(response.headers()[WWW_AUTHENTICATE], "Bearer realm=\"davhaven\"");
            }
            assert!(
                json.get("errors")
                    .is_none_or(|errors| errors.as_array().is_some_and(Vec::is_empty)),
                "{json}"
            );
            assert_eq!(
                response.headers().contains_key(RETRY_AFTER),
                *code == ProblemCode::RateLimited,
                "{}",
                code.code()
            );
        }
    }

    #[tokio::test]
    async fn internal_text_never_reaches_the_document() {
        let secret = "relation \"calendar_objects\" does not exist (password=hunter2)";
        let error = AppError::internal(std::io::Error::other(secret));
        let (response, json) = render(EdgeProblem::from(error)).await;
        assert_eq!(response.status().as_u16(), 500);
        assert!(!json.to_string().contains("hunter2"), "{json}");
        assert!(json.get("detail").is_none());

        let refused = AppError::invalid(SafeMessage::from_static("The display name is too long."));
        let (_, json) = render(EdgeProblem::from(refused)).await;
        assert_eq!(json["detail"], "The display name is too long.");
    }

    #[tokio::test]
    async fn rate_limits_tell_clients_when_to_come_back() {
        let error = AppError::rate_limited(core::time::Duration::from_secs(42));
        let (response, json) = render(EdgeProblem::from(error)).await;
        assert_eq!(response.status().as_u16(), 429);
        assert_eq!(response.headers()[RETRY_AFTER], "42");
        assert_eq!(json["code"], "rate-limited");
    }
}
