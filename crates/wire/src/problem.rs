//! RFC 9457 problem details and the `ProblemCode` catalog.
//!
//! Every failure a client can see is one row of the catalog: a stable kebab-case code, a title, the HTTP status of
//! the management API, the status and precondition element a DAV client receives and whether an MCP client should
//! retry. The catalog is the single source of `docs/problems.md` (`xtask problems-docs`); the mapping tables of the
//! protocol crates (`dav`, `api`, `mcp`, `web`) are tested against it exhaustively.
//!
//! [`ProblemCode::from_error`] is the canonical translation of an application error (an `ErrorKind` with an
//! optional `Precondition`) into a catalog row. Internal error text never reaches a client: a problem carries the
//! row's title, an optional client-safe `detail` and per-field errors, nothing else.

use davhaven_domain::{ErrorKind, Precondition, RequestId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::openapi::RefOr;
use utoipa::openapi::schema::{ObjectBuilder, Schema, Type};
use utoipa::{PartialSchema, ToSchema};

/// The namespace of problem type URIs: `urn:davhaven:problem:{code}`.
pub const PROBLEM_TYPE_PREFIX: &str = "urn:davhaven:problem:";

/// The description of the `ProblemCode` schema in the OpenAPI document.
const PROBLEM_CODE_DESCRIPTION: &str = "A row of the problem catalog: the stable `code` of an error response, for \
     example `uid-conflict`. New rows are added over time; clients treat unknown codes like the generic problem of \
     their HTTP status.";

macro_rules! problem_codes {
    (
        $(
            $(#[doc = $doc:literal])*
            $variant:ident => {
                code: $code:literal,
                title: $title:literal,
                http: $http:literal,
                dav: $dav:literal,
                element: $element:expr,
                retryable: $retryable:literal
            }
        ),+ $(,)?
    ) => {
        /// A row of the problem catalog: the stable `code` of an error response.
        ///
        /// The serialized form is the kebab-case code, for example `uid-conflict`. New rows are added over time;
        /// clients treat unknown codes like the generic problem of their HTTP status.
        ///
        /// The OpenAPI schema is written by hand below from the same literals the serde names come from: the
        /// derive of `ToSchema` does not read a `serde(rename)` that a `macro_rules` expansion produces, and
        /// would publish the Rust variant names instead of the codes a client receives.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
        pub enum ProblemCode {
            $( $(#[doc = $doc])* #[serde(rename = $code)] $variant ),+
        }

        impl PartialSchema for ProblemCode {
            fn schema() -> RefOr<Schema> {
                RefOr::T(Schema::Object(
                    ObjectBuilder::new()
                        .schema_type(Type::String)
                        .description(Some(PROBLEM_CODE_DESCRIPTION))
                        .enum_values(Some([ $( $code ),+ ]))
                        .build(),
                ))
            }
        }

        impl ToSchema for ProblemCode {}

        impl ProblemCode {
            /// Every code, in catalog order.
            pub const ALL: &'static [Self] = &[ $( Self::$variant ),+ ];

            /// The catalog row of the code.
            const fn row(self) -> &'static Row {
                match self {
                    $(
                        Self::$variant => &Row {
                            code: $code,
                            title: $title,
                            http: $http,
                            dav: $dav,
                            element: $element,
                            retryable: $retryable,
                            description: concat!($($doc, "\n"),*),
                        }
                    ),+
                }
            }
        }
    };
}

/// One row of the catalog.
struct Row {
    code: &'static str,
    title: &'static str,
    http: u16,
    dav: u16,
    element: Option<&'static str>,
    retryable: bool,
    /// The doc comment of the variant, one line per doc line.
    description: &'static str,
}

problem_codes! {
    /// The request cannot be parsed or is structurally malformed.
    BadRequest => { code: "bad-request", title: "Malformed request", http: 400, dav: 400, element: None, retryable: false },
    /// No valid credential was presented.
    Unauthenticated => { code: "unauthenticated", title: "Authentication required", http: 401, dav: 401, element: None, retryable: false },
    /// The caller may see the resource but is not permitted to do this.
    Forbidden => { code: "forbidden", title: "Not permitted", http: 403, dav: 403, element: Some("DAV:need-privileges"), retryable: false },
    /// The resource does not exist or is not visible to the caller (including other tenants' resources).
    NotFound => { code: "not-found", title: "Resource not found", http: 404, dav: 404, element: None, retryable: false },
    /// The method is not allowed on the resource.
    MethodNotAllowed => { code: "method-not-allowed", title: "Method not allowed", http: 405, dav: 405, element: None, retryable: false },
    /// The request conflicts with the current state of the resource.
    Conflict => { code: "conflict", title: "Conflict with the current state", http: 409, dav: 409, element: None, retryable: false },
    /// A conditional request header does not match the current state.
    PreconditionFailed => { code: "precondition-failed", title: "Precondition failed", http: 412, dav: 412, element: None, retryable: false },
    /// The request must be conditional.
    PreconditionRequired => { code: "precondition-required", title: "Precondition required", http: 428, dav: 428, element: None, retryable: false },
    /// The request or a value in it exceeds a size limit.
    PayloadTooLarge => { code: "payload-too-large", title: "Request too large", http: 413, dav: 413, element: None, retryable: false },
    /// The content type of the request is not accepted.
    UnsupportedMediaType => { code: "unsupported-media-type", title: "Unsupported media type", http: 415, dav: 415, element: None, retryable: false },
    /// The request is well formed but a value is invalid; `errors` lists the offending fields.
    ValidationFailed => { code: "validation-failed", title: "Validation failed", http: 422, dav: 400, element: None, retryable: false },
    /// The caller exceeded a rate limit; `Retry-After` says when to try again.
    RateLimited => { code: "rate-limited", title: "Too many requests", http: 429, dav: 429, element: None, retryable: true },
    /// An unexpected failure on the server.
    Internal => { code: "internal", title: "Internal error", http: 500, dav: 500, element: None, retryable: false },
    /// The operation is not available.
    NotImplemented => { code: "not-implemented", title: "Not implemented", http: 501, dav: 501, element: None, retryable: false },
    /// A dependency is unavailable; the request may be repeated later.
    Unavailable => { code: "unavailable", title: "Service unavailable", http: 503, dav: 503, element: None, retryable: true },
    /// An `Idempotency-Key` was reused with a different request.
    IdempotencyKeyReuse => { code: "idempotency-key-reuse", title: "Idempotency key reused", http: 422, dav: 400, element: None, retryable: false },
    /// A request with the same `Idempotency-Key` is still being processed.
    IdempotencyInProgress => { code: "idempotency-in-progress", title: "Request in progress", http: 409, dav: 409, element: None, retryable: true },
    /// The original response contained a secret, or could not be stored, so it cannot be replayed; the original
    /// request did take effect.
    SecretNotReplayable => { code: "secret-not-replayable", title: "Secret cannot be replayed", http: 409, dav: 409, element: None, retryable: false },
    /// The feature is disabled for this deployment or tenant.
    FeatureNotEnabled => { code: "feature-not-enabled", title: "Feature not enabled", http: 409, dav: 403, element: None, retryable: false },
    /// The calendar data is not valid iCalendar or violates a limit (`CALDAV:valid-calendar-data`).
    InvalidCalendarData => { code: "invalid-calendar-data", title: "Invalid calendar data", http: 422, dav: 403, element: Some("CALDAV:valid-calendar-data"), retryable: false },
    /// The data breaks the rules for calendar object resources (`CALDAV:valid-calendar-object-resource`).
    InvalidCalendarObject => { code: "invalid-calendar-object", title: "Invalid calendar object resource", http: 422, dav: 403, element: Some("CALDAV:valid-calendar-object-resource"), retryable: false },
    /// The calendar does not accept this component type (`CALDAV:supported-calendar-component`).
    UnsupportedCalendarComponent => { code: "unsupported-calendar-component", title: "Unsupported calendar component", http: 422, dav: 403, element: Some("CALDAV:supported-calendar-component"), retryable: false },
    /// The content is not iCalendar (`CALDAV:supported-calendar-data`).
    UnsupportedCalendarData => { code: "unsupported-calendar-data", title: "Unsupported calendar data", http: 415, dav: 403, element: Some("CALDAV:supported-calendar-data"), retryable: false },
    /// Another object of the calendar has the UID (`CALDAV:no-uid-conflict`).
    UidConflict => { code: "uid-conflict", title: "UID already in use", http: 409, dav: 403, element: Some("CALDAV:no-uid-conflict"), retryable: false },
    /// The resource is larger than the maximum (`CALDAV:max-resource-size`).
    ResourceTooLarge => { code: "resource-too-large", title: "Resource too large", http: 413, dav: 403, element: Some("CALDAV:max-resource-size"), retryable: false },
    /// A date is before the minimum (`CALDAV:min-date-time`).
    DateTooEarly => { code: "date-too-early", title: "Date too early", http: 422, dav: 403, element: Some("CALDAV:min-date-time"), retryable: false },
    /// A date is after the maximum (`CALDAV:max-date-time`).
    DateTooLate => { code: "date-too-late", title: "Date too late", http: 422, dav: 403, element: Some("CALDAV:max-date-time"), retryable: false },
    /// The recurrence set has too many instances (`CALDAV:max-instances`).
    TooManyInstances => { code: "too-many-instances", title: "Too many instances", http: 422, dav: 403, element: Some("CALDAV:max-instances"), retryable: false },
    /// An instance has too many attendees (`CALDAV:max-attendees-per-instance`).
    TooManyAttendees => { code: "too-many-attendees", title: "Too many attendees", http: 422, dav: 403, element: Some("CALDAV:max-attendees-per-instance"), retryable: false },
    /// The owner already has a scheduling object with the UID (`CALDAV:unique-scheduling-object-resource`).
    SchedulingUidConflict => { code: "scheduling-uid-conflict", title: "Scheduling object already exists", http: 409, dav: 403, element: Some("CALDAV:unique-scheduling-object-resource"), retryable: false },
    /// Components disagree on the organizer (`CALDAV:same-organizer-in-all-components`).
    OrganizerMismatch => { code: "organizer-mismatch", title: "Organizer differs between components", http: 422, dav: 403, element: Some("CALDAV:same-organizer-in-all-components"), retryable: false },
    /// The actor may not create a meeting with this organizer (`CALDAV:organizer-allowed`).
    OrganizerNotAllowed => { code: "organizer-not-allowed", title: "Organizer not allowed", http: 403, dav: 403, element: Some("CALDAV:organizer-allowed"), retryable: false },
    /// An organizer change that is not allowed (`CALDAV:allowed-organizer-scheduling-object-change`).
    OrganizerChangeNotAllowed => { code: "organizer-change-not-allowed", title: "Organizer change not allowed", http: 403, dav: 403, element: Some("CALDAV:allowed-organizer-scheduling-object-change"), retryable: false },
    /// An attendee changed more than their own copy (`CALDAV:allowed-attendee-scheduling-object-change`).
    AttendeeChangeNotAllowed => { code: "attendee-change-not-allowed", title: "Attendee change not allowed", http: 403, dav: 403, element: Some("CALDAV:allowed-attendee-scheduling-object-change"), retryable: false },
    /// The iTIP message is not valid (`CALDAV:valid-scheduling-message`).
    InvalidSchedulingMessage => { code: "invalid-scheduling-message", title: "Invalid scheduling message", http: 422, dav: 400, element: Some("CALDAV:valid-scheduling-message"), retryable: false },
    /// The sync token is foreign, garbled, from another epoch or pruned (`DAV:valid-sync-token`).
    SyncTokenExpired => { code: "sync-token-expired", title: "Sync token expired", http: 410, dav: 403, element: Some("DAV:valid-sync-token"), retryable: false },
    /// The query matches too many resources (`DAV:number-of-matches-within-limits`).
    TooManyMatches => { code: "too-many-matches", title: "Too many matches", http: 422, dav: 507, element: Some("DAV:number-of-matches-within-limits"), retryable: false },
    /// `Depth: infinity` is refused (`DAV:propfind-finite-depth`).
    DepthInfinityRefused => { code: "depth-infinity-refused", title: "Infinite depth refused", http: 400, dav: 403, element: Some("DAV:propfind-finite-depth"), retryable: false },
    /// The query filter is invalid or exceeds a limit (`CALDAV:valid-filter`).
    InvalidFilter => { code: "invalid-filter", title: "Invalid filter", http: 422, dav: 403, element: Some("CALDAV:valid-filter"), retryable: false },
    /// The target of MKCALENDAR or MKCOL already exists (`DAV:resource-must-be-null`).
    ResourceExists => { code: "resource-exists", title: "Resource already exists", http: 409, dav: 405, element: Some("DAV:resource-must-be-null"), retryable: false },
    /// A protected property cannot be changed (`DAV:cannot-modify-protected-property`).
    ProtectedProperty => { code: "protected-property", title: "Protected property", http: 403, dav: 403, element: Some("DAV:cannot-modify-protected-property"), retryable: false },
    /// Sharing is not allowed for this calendar or tenant.
    SharingNotAllowed => { code: "sharing-not-allowed", title: "Sharing not allowed", http: 403, dav: 403, element: None, retryable: false },
    /// The sharee is not a valid target, for example an external address.
    InvalidSharee => { code: "invalid-sharee", title: "Invalid sharee", http: 422, dav: 403, element: None, retryable: false },
    /// The name of a principal write belongs to a deleted principal that has not been purged yet (a write without
    /// `If-None-Match: *`; with it the answer is 412, like for every name that exists).
    NameReserved => { code: "name-reserved", title: "Name reserved", http: 409, dav: 409, element: None, retryable: false },
    /// The external reference belongs to a deleted principal that has not been purged yet.
    ExternalRefReserved => { code: "external-ref-reserved", title: "External reference reserved", http: 409, dav: 409, element: None, retryable: false },
    /// An address belongs to a deleted principal that has not been purged yet.
    AddressReserved => { code: "address-reserved", title: "Address reserved", http: 409, dav: 409, element: None, retryable: false },
    /// The report is not one the resource supports (`DAV:supported-report`, RFC 3253 section 3.6).
    UnsupportedReport => { code: "unsupported-report", title: "Unsupported report", http: 400, dav: 403, element: Some("DAV:supported-report"), retryable: false },
    /// A request names more resources than a limit allows: the hrefs of a `calendar-multiget`, the sharees of a
    /// `CS:share` (`DAV:number-of-matches-within-limits`). A query or a synchronization that matches too much is
    /// `too-many-matches`, which has the same element and another status.
    TooManyHrefs => { code: "too-many-hrefs", title: "Too many resources named", http: 422, dav: 403, element: Some("DAV:number-of-matches-within-limits"), retryable: false },
    /// A `sync-collection` asks for `sync-level` infinite (`DAV:sync-traversal-supported`, RFC 6578 sections 3.2 and
    /// 3.3). RFC 6578 gives no status of its own for it; like the other preconditions of the report
    /// (`DAV:valid-sync-token`) it is 403, the status RFC 4918 section 16 uses with a precondition element.
    SyncTraversalUnsupported => { code: "sync-traversal-unsupported", title: "Sync traversal not supported", http: 422, dav: 403, element: Some("DAV:sync-traversal-supported"), retryable: false },
    /// A `MOVE` or `COPY` names a destination on another server, which this server does not move to (RFC 4918
    /// sections 9.8.5 and 9.9.4).
    ForeignDestination => { code: "foreign-destination", title: "Destination on another server", http: 422, dav: 502, element: None, retryable: false },
}

impl ProblemCode {
    /// The stable kebab-case code (the last segment of the problem type URI).
    pub const fn code(self) -> &'static str {
        self.row().code
    }

    /// The short, human-readable title of the problem type (the same for every occurrence).
    pub const fn title(self) -> &'static str {
        self.row().title
    }

    /// The HTTP status of the management API, the web pages and the feeds.
    pub const fn http_status(self) -> u16 {
        self.row().http
    }

    /// The status a DAV client receives.
    pub const fn dav_status(self) -> u16 {
        self.row().dav
    }

    /// The precondition or postcondition element of the DAV error body, written as `NAMESPACE:local-name`
    /// (`DAV:need-privileges`, `CALDAV:valid-calendar-data`), when the problem has one.
    pub const fn dav_element(self) -> Option<&'static str> {
        self.row().element
    }

    /// Whether an MCP client may repeat the same tool call later (reported in the tool result).
    pub const fn retryable(self) -> bool {
        self.row().retryable
    }

    /// When the problem happens: the documentation of the row, on one line (the text of `docs/problems.md`).
    pub fn description(self) -> String {
        self.row()
            .description
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The problem type URI: `urn:davhaven:problem:{code}`.
    pub fn type_uri(self) -> String {
        format!("{PROBLEM_TYPE_PREFIX}{}", self.code())
    }

    /// Looks a code up by its kebab-case spelling.
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|candidate| candidate.code() == code)
    }

    /// The row a precondition maps to; `None` for preconditions this release does not know.
    pub fn from_precondition(precondition: &Precondition) -> Option<Self> {
        Some(match precondition {
            Precondition::NeedPrivileges(_) => Self::Forbidden,
            Precondition::ValidCalendarData(_) => Self::InvalidCalendarData,
            Precondition::ValidCalendarObjectResource => Self::InvalidCalendarObject,
            Precondition::SupportedCalendarComponent => Self::UnsupportedCalendarComponent,
            Precondition::SupportedCalendarData => Self::UnsupportedCalendarData,
            Precondition::NoUidConflict(_) => Self::UidConflict,
            Precondition::MaxResourceSize => Self::ResourceTooLarge,
            Precondition::MinDateTime => Self::DateTooEarly,
            Precondition::MaxDateTime => Self::DateTooLate,
            Precondition::MaxInstances => Self::TooManyInstances,
            Precondition::MaxAttendeesPerInstance => Self::TooManyAttendees,
            Precondition::UniqueSchedulingObjectResource(_) => Self::SchedulingUidConflict,
            Precondition::SameOrganizerInAllComponents => Self::OrganizerMismatch,
            Precondition::OrganizerAllowed => Self::OrganizerNotAllowed,
            Precondition::AllowedOrganizerSchedulingObjectChange => Self::OrganizerChangeNotAllowed,
            Precondition::AllowedAttendeeSchedulingObjectChange => Self::AttendeeChangeNotAllowed,
            Precondition::ValidSchedulingMessage => Self::InvalidSchedulingMessage,
            Precondition::ValidSyncToken => Self::SyncTokenExpired,
            Precondition::NumberOfMatchesWithinLimits => Self::TooManyMatches,
            Precondition::PropfindFiniteDepth => Self::DepthInfinityRefused,
            Precondition::ValidFilter => Self::InvalidFilter,
            Precondition::ResourceMustBeNull => Self::ResourceExists,
            Precondition::CannotModifyProtectedProperty => Self::ProtectedProperty,
            Precondition::SharingNotAllowed => Self::SharingNotAllowed,
            Precondition::InvalidSharee(_) => Self::InvalidSharee,
            Precondition::FeatureNotEnabled => Self::FeatureNotEnabled,
            Precondition::NameReserved => Self::NameReserved,
            Precondition::ExternalRefReserved => Self::ExternalRefReserved,
            Precondition::AddressReserved => Self::AddressReserved,
            _ => return None,
        })
    }

    /// The row an error kind maps to when no precondition refines it.
    pub const fn from_kind(kind: ErrorKind) -> Self {
        match kind {
            ErrorKind::NotFound => Self::NotFound,
            ErrorKind::Unauthenticated => Self::Unauthenticated,
            ErrorKind::Forbidden => Self::Forbidden,
            ErrorKind::Conflict => Self::Conflict,
            ErrorKind::PreconditionFailed => Self::PreconditionFailed,
            ErrorKind::PreconditionRequired => Self::PreconditionRequired,
            ErrorKind::Invalid => Self::ValidationFailed,
            ErrorKind::TooLarge => Self::PayloadTooLarge,
            ErrorKind::RateLimited => Self::RateLimited,
            ErrorKind::Unavailable => Self::Unavailable,
            ErrorKind::Unsupported => Self::NotImplemented,
            ErrorKind::Internal => Self::Internal,
        }
    }

    /// The canonical translation of an application error: the precondition decides when there is one that this
    /// release knows, the error kind otherwise.
    pub fn from_error(kind: ErrorKind, precondition: Option<&Precondition>) -> Self {
        precondition
            .and_then(Self::from_precondition)
            .unwrap_or_else(|| Self::from_kind(kind))
    }
}

/// One invalid field of a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct FieldProblem {
    /// A JSON Pointer (RFC 6901) to the offending value in the request body, `""` for the whole body.
    pub pointer: String,
    /// A short kebab-case code of the rule that was violated, for example `required` or `too-long`.
    pub code: String,
    /// A client-safe explanation.
    pub message: String,
}

impl FieldProblem {
    /// Creates a field problem.
    pub fn new(pointer: impl Into<String>, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            pointer: pointer.into(),
            code: code.into(),
            message: message.into(),
        }
    }
}

/// A problem details document (RFC 9457) as returned by the management API and carried in MCP tool results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct ProblemDetails {
    /// `urn:davhaven:problem:{code}`.
    #[serde(rename = "type")]
    pub type_uri: String,
    /// The title of the problem type.
    pub title: String,
    /// The HTTP status of the response.
    pub status: u16,
    /// A client-safe explanation of this occurrence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The catalog code.
    pub code: ProblemCode,
    /// The id of the request, also sent as `X-Request-Id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Uuid>)]
    pub request_id: Option<RequestId>,
    /// The invalid fields, for validation problems.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<FieldProblem>,
}

impl ProblemDetails {
    /// The problem of a catalog row, with its title and HTTP status.
    pub fn new(code: ProblemCode) -> Self {
        Self {
            type_uri: code.type_uri(),
            title: code.title().to_owned(),
            status: code.http_status(),
            detail: None,
            code,
            request_id: None,
            errors: Vec::new(),
        }
    }

    /// Sets the client-safe detail text.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Sets the request id.
    #[must_use]
    pub fn with_request_id(mut self, request_id: RequestId) -> Self {
        self.request_id = Some(request_id);
        self
    }

    /// Adds one invalid field.
    #[must_use]
    pub fn with_error(mut self, error: FieldProblem) -> Self {
        self.errors.push(error);
        self
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use davhaven_domain::{Href, Privilege};

    use super::*;

    fn href() -> Href {
        Href::parse("/dav/calendars/acme/anna/work/x.ics").unwrap()
    }

    #[test]
    fn every_row_says_when_it_happens_on_one_line() {
        for code in ProblemCode::ALL {
            let description = code.description();
            assert!(description.ends_with('.'), "{}: {description}", code.code());
            assert!(
                !description.contains('\n') && !description.contains("  "),
                "{description}"
            );
        }
        assert_eq!(
            ProblemCode::NotFound.description(),
            "The resource does not exist or is not visible to the caller (including other tenants' resources)."
        );
        // A doc comment of several lines is joined with single spaces.
        assert!(
            ProblemCode::NameReserved
                .description()
                .starts_with("The name of a principal write belongs to a deleted principal that has not been purged yet (a write without `If-None-Match: *`;")
        );
    }

    #[test]
    fn codes_are_unique_kebab_case_and_match_their_serde_name() {
        let mut seen = HashSet::new();
        for code in ProblemCode::ALL {
            let text = code.code();
            assert!(seen.insert(text), "duplicate code {text}");
            assert!(
                !text.is_empty()
                    && !text.starts_with('-')
                    && !text.ends_with('-')
                    && text.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
                "{text}"
            );
            assert_eq!(serde_json::to_value(code).unwrap(), serde_json::json!(text));
            assert_eq!(ProblemCode::from_code(text), Some(*code));
            assert!(code.type_uri().ends_with(text));
        }
        assert_eq!(ProblemCode::from_code("nope"), None);
    }

    #[test]
    fn statuses_and_elements_are_plausible() {
        for code in ProblemCode::ALL {
            assert!((400..600).contains(&code.http_status()), "{code:?}");
            assert!((400..600).contains(&code.dav_status()), "{code:?}");
            assert_ne!(code.title(), "");
            if let Some(element) = code.dav_element() {
                let (namespace, local) = element.split_once(':').unwrap();
                assert!(matches!(namespace, "DAV" | "CALDAV"), "{element}");
                assert!(!local.is_empty() && local.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'));
            }
        }
        assert_eq!(ProblemCode::Unauthenticated.http_status(), 401);
        assert_eq!(ProblemCode::SyncTokenExpired.http_status(), 410);
        assert_eq!(ProblemCode::SyncTokenExpired.dav_status(), 403);
        assert_eq!(ProblemCode::PreconditionRequired.http_status(), 428);
        assert!(ProblemCode::RateLimited.retryable());
        assert!(!ProblemCode::Forbidden.retryable());
    }

    #[test]
    fn dav_elements_are_unique_per_status() {
        // The element names the condition and the status says what the protocol does about it: the limit of the
        // hrefs of a request (403) and the limit of what a query matches (507) are one condition of RFC 4918.
        let mut elements = HashSet::new();
        for code in ProblemCode::ALL {
            if let Some(element) = code.dav_element() {
                assert!(
                    elements.insert((element, code.dav_status())),
                    "element {element} used twice with status {}",
                    code.dav_status()
                );
            }
        }
    }

    #[test]
    fn the_answers_the_rfcs_define_for_the_dav_layer_are_rows() {
        let expected = [
            (ProblemCode::UnsupportedReport, 403, Some("DAV:supported-report")),
            (
                ProblemCode::TooManyHrefs,
                403,
                Some("DAV:number-of-matches-within-limits"),
            ),
            (
                ProblemCode::TooManyMatches,
                507,
                Some("DAV:number-of-matches-within-limits"),
            ),
            (
                ProblemCode::SyncTraversalUnsupported,
                403,
                Some("DAV:sync-traversal-supported"),
            ),
            (ProblemCode::ForeignDestination, 502, None),
        ];
        for (code, status, element) in expected {
            assert_eq!(code.dav_status(), status, "{}", code.code());
            assert_eq!(code.dav_element(), element, "{}", code.code());
            assert!(!code.retryable(), "{}", code.code());
        }
        // No precondition of the application leads to them: the DAV layer finds these conditions itself.
        for precondition in [Precondition::NumberOfMatchesWithinLimits, Precondition::ValidSyncToken] {
            let row = ProblemCode::from_precondition(&precondition).unwrap();
            assert!(
                !matches!(
                    row,
                    ProblemCode::UnsupportedReport
                        | ProblemCode::TooManyHrefs
                        | ProblemCode::SyncTraversalUnsupported
                        | ProblemCode::ForeignDestination
                ),
                "{}",
                row.code()
            );
        }
    }

    #[test]
    fn every_error_kind_maps_to_its_generic_code() {
        let expected = [
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
        assert_eq!(expected.len(), ErrorKind::ALL.len());
        for (kind, code) in expected {
            assert_eq!(ProblemCode::from_kind(kind).code(), code, "{kind}");
            assert_eq!(ProblemCode::from_error(kind, None).code(), code, "{kind}");
        }
    }

    fn precondition_cases() -> Vec<(Precondition, &'static str, &'static str)> {
        vec![
            (
                Precondition::need_privilege(href(), Privilege::Read),
                "forbidden",
                "DAV:need-privileges",
            ),
            (
                Precondition::ValidCalendarData("bad".to_owned()),
                "invalid-calendar-data",
                "CALDAV:valid-calendar-data",
            ),
            (
                Precondition::ValidCalendarObjectResource,
                "invalid-calendar-object",
                "CALDAV:valid-calendar-object-resource",
            ),
            (
                Precondition::SupportedCalendarComponent,
                "unsupported-calendar-component",
                "CALDAV:supported-calendar-component",
            ),
            (
                Precondition::SupportedCalendarData,
                "unsupported-calendar-data",
                "CALDAV:supported-calendar-data",
            ),
            (
                Precondition::NoUidConflict(href()),
                "uid-conflict",
                "CALDAV:no-uid-conflict",
            ),
            (
                Precondition::MaxResourceSize,
                "resource-too-large",
                "CALDAV:max-resource-size",
            ),
            (Precondition::MinDateTime, "date-too-early", "CALDAV:min-date-time"),
            (Precondition::MaxDateTime, "date-too-late", "CALDAV:max-date-time"),
            (Precondition::MaxInstances, "too-many-instances", "CALDAV:max-instances"),
            (
                Precondition::MaxAttendeesPerInstance,
                "too-many-attendees",
                "CALDAV:max-attendees-per-instance",
            ),
            (
                Precondition::UniqueSchedulingObjectResource(href()),
                "scheduling-uid-conflict",
                "CALDAV:unique-scheduling-object-resource",
            ),
            (
                Precondition::SameOrganizerInAllComponents,
                "organizer-mismatch",
                "CALDAV:same-organizer-in-all-components",
            ),
            (
                Precondition::OrganizerAllowed,
                "organizer-not-allowed",
                "CALDAV:organizer-allowed",
            ),
            (
                Precondition::AllowedOrganizerSchedulingObjectChange,
                "organizer-change-not-allowed",
                "CALDAV:allowed-organizer-scheduling-object-change",
            ),
            (
                Precondition::AllowedAttendeeSchedulingObjectChange,
                "attendee-change-not-allowed",
                "CALDAV:allowed-attendee-scheduling-object-change",
            ),
        ]
    }

    fn dav_precondition_cases() -> Vec<(Precondition, &'static str, &'static str)> {
        vec![
            (
                Precondition::ValidSchedulingMessage,
                "invalid-scheduling-message",
                "CALDAV:valid-scheduling-message",
            ),
            (
                Precondition::ValidSyncToken,
                "sync-token-expired",
                "DAV:valid-sync-token",
            ),
            (
                Precondition::NumberOfMatchesWithinLimits,
                "too-many-matches",
                "DAV:number-of-matches-within-limits",
            ),
            (
                Precondition::PropfindFiniteDepth,
                "depth-infinity-refused",
                "DAV:propfind-finite-depth",
            ),
            (Precondition::ValidFilter, "invalid-filter", "CALDAV:valid-filter"),
            (
                Precondition::ResourceMustBeNull,
                "resource-exists",
                "DAV:resource-must-be-null",
            ),
            (
                Precondition::CannotModifyProtectedProperty,
                "protected-property",
                "DAV:cannot-modify-protected-property",
            ),
        ]
    }

    #[test]
    fn every_precondition_maps_to_a_distinct_code_with_its_dav_element() {
        let mut cases = precondition_cases();
        cases.extend(dav_precondition_cases());
        for (precondition, code, element) in &cases {
            let mapped = ProblemCode::from_precondition(precondition).unwrap();
            assert_eq!(mapped.code(), *code, "{}", precondition.code());
            assert_eq!(mapped.dav_element(), Some(*element), "{}", precondition.code());
            assert_eq!(
                ProblemCode::from_error(ErrorKind::Invalid, Some(precondition)),
                mapped,
                "the precondition wins over the kind"
            );
        }
        let without_element = [
            (Precondition::SharingNotAllowed, "sharing-not-allowed"),
            (Precondition::InvalidSharee(href()), "invalid-sharee"),
            (Precondition::FeatureNotEnabled, "feature-not-enabled"),
            (Precondition::NameReserved, "name-reserved"),
            (Precondition::ExternalRefReserved, "external-ref-reserved"),
            (Precondition::AddressReserved, "address-reserved"),
        ];
        for (precondition, code) in &without_element {
            let mapped = ProblemCode::from_precondition(precondition).unwrap();
            assert_eq!(mapped.code(), *code);
            assert_eq!(mapped.dav_element(), None);
        }
        let mut distinct: HashSet<ProblemCode> = HashSet::new();
        for (precondition, _, _) in &cases {
            distinct.insert(ProblemCode::from_precondition(precondition).unwrap());
        }
        assert_eq!(distinct.len(), cases.len(), "no two preconditions share a code");
    }

    /// The enumeration a schema lists, as text.
    fn listed(schema: &serde_json::Value) -> Vec<String> {
        schema["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn the_schemas_list_the_codes_a_client_receives_not_the_variant_names() {
        let expected: Vec<String> = ProblemCode::ALL.iter().map(|code| code.code().to_owned()).collect();
        let openapi = serde_json::to_value(ProblemCode::schema()).unwrap();
        assert_eq!(openapi["type"], "string");
        assert_eq!(listed(&openapi), expected, "the OpenAPI enumeration");
        assert!(openapi["description"].as_str().unwrap().contains("problem catalog"));
        assert_eq!(ProblemCode::name(), "ProblemCode");
        let json_schema = serde_json::to_value(schemars::schema_for!(ProblemCode)).unwrap();
        let mut from_schemars = Vec::new();
        for alternative in json_schema["oneOf"].as_array().into_iter().flatten() {
            from_schemars.push(alternative["const"].as_str().unwrap().to_owned());
        }
        if from_schemars.is_empty() {
            from_schemars = listed(&json_schema);
        }
        assert_eq!(from_schemars, expected, "the JSON schema of the MCP tools");
        // And what the server writes is one of the listed values.
        for code in ProblemCode::ALL {
            let wire = serde_json::to_value(code).unwrap();
            assert!(expected.contains(&wire.as_str().unwrap().to_owned()), "{code:?}");
        }
    }

    #[test]
    fn problem_details_follow_rfc_9457_and_omit_empty_members() {
        let request_id = RequestId::parse("018f3c1e-7b2a-7c3d-9e4f-0123456789ab").unwrap();
        let problem = ProblemDetails::new(ProblemCode::ValidationFailed)
            .with_request_id(request_id)
            .with_error(FieldProblem::new("/display_name", "required", "must not be empty"));
        let json = serde_json::to_value(&problem).unwrap();
        assert_eq!(json["type"], "urn:davhaven:problem:validation-failed");
        assert_eq!(json["title"], "Validation failed");
        assert_eq!(json["status"], 422);
        assert_eq!(json["code"], "validation-failed");
        assert_eq!(json["request_id"], "018f3c1e-7b2a-7c3d-9e4f-0123456789ab");
        assert_eq!(json["errors"][0]["pointer"], "/display_name");
        assert!(json.get("detail").is_none());
        let plain = serde_json::to_value(ProblemDetails::new(ProblemCode::NotFound)).unwrap();
        assert!(plain.get("errors").is_none());
        assert!(plain.get("request_id").is_none());
        let detailed = ProblemDetails::new(ProblemCode::Conflict).with_detail("the slug is taken");
        assert_eq!(detailed.detail.as_deref(), Some("the slug is taken"));
        let back: ProblemDetails = serde_json::from_value(json).unwrap();
        assert_eq!(back, problem);
    }
}
