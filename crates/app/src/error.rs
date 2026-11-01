//! `AppError`: error kind, optional precondition, safe public message and source.
//!
//! Every service method returns [`AppError`] (`ENGINEERING_RULES` R5). It carries what a protocol crate needs to
//! answer a client and nothing else:
//!
//! * the [`ErrorKind`] (the coarse class: 404, 403, 409, ...);
//! * an optional [`Precondition`] that refines it (`CALDAV:no-uid-conflict`, `DAV:need-privileges`, ...);
//! * a [`SafeMessage`], the only text that may reach a client;
//! * for rate limits, how long to wait;
//! * for invalid input, the fields that are wrong ([`FieldError`]: a JSON pointer, a stable code and a message), which
//!   the API shows as `errors[{pointer, code, message}]` of the problem document (PLAN 2.10);
//! * the *source* error, for logs and operators only. It is reachable through [`std::error::Error::source`] and is
//!   never part of `Display`, so it cannot leak by formatting the error into a response.
//!
//! Each protocol crate maps an `AppError` exactly once through an exhaustively tested table (`ProblemCode` in
//! `davhaven-wire` is the shared catalog). The conversions from [`StoreError`], [`PortError`] and [`IcalError`]
//! defined here are the default mappings; use cases that know more (for example the href of the object that
//! caused a UID conflict) refine the error with [`AppError::with_precondition`].

use core::fmt;
use std::borrow::Cow;
use std::error::Error as StdError;
use std::time::Duration;

use davhaven_domain::{ErrorKind, Href, Precondition, Privilege};
use davhaven_ical::{ErrorContext, IcalError, LimitKind};
use davhaven_ports::{PortError, PortErrorKind, StoreError, UniqueKey};
use davhaven_wire::{FieldProblem, ProblemCode, ProblemDetails};

/// The result type of every service method.
pub type AppResult<T> = Result<T, AppError>;

/// The longest text a [`SafeMessage`] built from dynamic text may have, in characters.
const MAX_SAFE_MESSAGE_CHARS: usize = 200;

/// Text that may be shown to a client.
///
/// A `SafeMessage` is built from a static string or from text that was written for clients (validation messages
/// of the iCalendar layer), which is stripped of control characters and shortened. There is deliberately no
/// conversion from `String` or from an error's `Display` output, so adapter text cannot reach a response by
/// accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeMessage(Cow<'static, str>);

impl SafeMessage {
    /// A message from a string literal.
    pub const fn from_static(text: &'static str) -> Self {
        Self(Cow::Borrowed(text))
    }

    /// A message from text that was written for clients: control characters become spaces, runs of whitespace
    /// collapse, the text is trimmed and shortened to 200 characters. Empty text yields the generic message of
    /// [`ErrorKind::Invalid`].
    pub fn sanitized(text: &str) -> Self {
        let mut clean = String::with_capacity(text.len().min(MAX_SAFE_MESSAGE_CHARS));
        let mut pending_space = false;
        for c in text.chars() {
            if c.is_whitespace() || c.is_control() {
                pending_space = !clean.is_empty();
                continue;
            }
            if pending_space {
                clean.push(' ');
                pending_space = false;
            }
            clean.push(c);
            if clean.chars().count() >= MAX_SAFE_MESSAGE_CHARS {
                break;
            }
        }
        if clean.is_empty() {
            return Self::for_kind(ErrorKind::Invalid);
        }
        Self(Cow::Owned(clean))
    }

    /// The generic message of an error kind.
    pub const fn for_kind(kind: ErrorKind) -> Self {
        Self::from_static(match kind {
            ErrorKind::NotFound => "The resource was not found.",
            ErrorKind::Unauthenticated => "Authentication is required.",
            ErrorKind::Forbidden => "You are not permitted to do this.",
            ErrorKind::Conflict => "The request conflicts with the current state.",
            ErrorKind::PreconditionFailed => "The resource has changed; reload it and try again.",
            ErrorKind::PreconditionRequired => "This request must be conditional.",
            ErrorKind::Invalid => "The request is invalid.",
            ErrorKind::TooLarge => "The request is too large.",
            ErrorKind::RateLimited => "Too many requests; try again later.",
            ErrorKind::Unavailable => "The service is temporarily unavailable.",
            ErrorKind::Unsupported => "This operation is not available.",
            ErrorKind::Internal => "An internal error occurred.",
        })
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SafeMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One invalid field of a request body: where it is, what is wrong in machine-readable form, and a client-safe
/// description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldError {
    /// The RFC 6901 JSON pointer of the field in the request body, for example `/url` or `/events`.
    pub pointer: &'static str,
    /// A stable, machine-readable code, a short kebab-case word such as `too-long`, `not-allowed` or `empty`.
    pub code: &'static str,
    /// What is wrong, for people.
    pub message: SafeMessage,
}

/// The error of the application layer.
#[derive(Debug)]
pub struct AppError {
    kind: ErrorKind,
    precondition: Option<Box<Precondition>>,
    public_message: SafeMessage,
    retry_after: Option<Duration>,
    field_errors: Vec<FieldError>,
    source: Option<Box<dyn StdError + Send + Sync>>,
}

impl AppError {
    /// An error of `kind` with the generic message of the kind.
    pub const fn new(kind: ErrorKind) -> Self {
        Self::with_message(kind, SafeMessage::for_kind(kind))
    }

    /// An error of `kind` with a specific client-safe message.
    pub const fn with_message(kind: ErrorKind, public_message: SafeMessage) -> Self {
        Self {
            kind,
            precondition: None,
            public_message,
            retry_after: None,
            field_errors: Vec::new(),
            source: None,
        }
    }

    /// The only allowed stub (`ENGINEERING_RULES` R5): the operation is not implemented yet.
    ///
    /// CI lists every remaining call (`xtask unsupported`), warns on pull requests and fails release tags.
    pub const fn unsupported() -> Self {
        Self::new(ErrorKind::Unsupported)
    }

    /// The resource does not exist or is invisible to the caller.
    pub const fn not_found() -> Self {
        Self::new(ErrorKind::NotFound)
    }

    /// The caller did not authenticate or the credential is not valid.
    pub const fn unauthenticated() -> Self {
        Self::new(ErrorKind::Unauthenticated)
    }

    /// The caller may see the resource but may not do this.
    pub const fn forbidden() -> Self {
        Self::new(ErrorKind::Forbidden)
    }

    /// The caller lacks `privilege` on the resource at `href` (`DAV:need-privileges`).
    pub fn need_privilege(href: Href, privilege: Privilege) -> Self {
        Self::forbidden().with_precondition(Precondition::need_privilege(href, privilege))
    }

    /// The request conflicts with the current state.
    pub const fn conflict() -> Self {
        Self::new(ErrorKind::Conflict)
    }

    /// A conditional header or version check failed.
    pub const fn precondition_failed() -> Self {
        Self::new(ErrorKind::PreconditionFailed)
    }

    /// The request must be conditional.
    pub const fn precondition_required() -> Self {
        Self::new(ErrorKind::PreconditionRequired)
    }

    /// The request is invalid; `message` says why in client-safe words.
    pub const fn invalid(message: SafeMessage) -> Self {
        Self::with_message(ErrorKind::Invalid, message)
    }

    /// A value exceeds a size limit.
    pub const fn too_large() -> Self {
        Self::new(ErrorKind::TooLarge)
    }

    /// The caller exceeded a rate limit and should wait `retry_after`.
    pub const fn rate_limited(retry_after: Duration) -> Self {
        let mut error = Self::new(ErrorKind::RateLimited);
        error.retry_after = Some(retry_after);
        error
    }

    /// A dependency is unavailable; the request may be repeated later.
    pub const fn unavailable() -> Self {
        Self::new(ErrorKind::Unavailable)
    }

    /// The feature is disabled for this deployment or tenant (a disabled provider, tenant feeds, inbound iTIP).
    ///
    /// A conflict refined by [`Precondition::FeatureNotEnabled`], which every protocol crate renders as the catalog
    /// row `feature-not-enabled` (409 on the management API, 403 on DAV) instead of the generic `conflict`. The row
    /// comes from the precondition like every other refinement, so `ProblemCode::from_error` stays the one rule.
    pub fn feature_not_enabled() -> Self {
        Self::with_message(
            ErrorKind::Conflict,
            SafeMessage::from_static("This feature is not enabled."),
        )
        .with_precondition(Precondition::FeatureNotEnabled)
    }

    /// The name of a principal write belongs to a **deleted principal that has not been purged yet**: the write has no
    /// `If-None-Match: *` (which answers 412 for every name that exists, with no hint about a hidden principal), so it
    /// learns why it conflicts. A conflict refined by [`Precondition::NameReserved`] (409 `name-reserved`); see
    /// [`AppError::external_ref_reserved`] for the reason the reservations have codes of their own.
    pub fn name_reserved() -> Self {
        Self::with_message(
            ErrorKind::Conflict,
            SafeMessage::from_static("The name belongs to a deleted principal that has not been purged yet."),
        )
        .with_precondition(Precondition::NameReserved)
    }

    /// The external reference of a principal write belongs to a **deleted principal that has not been purged yet**.
    ///
    /// A deleted principal is hidden (listings and the `external_ref` filter no longer show it) but keeps its unique
    /// values until the purge, so a create that reuses one must be told apart from a conflict with a live principal:
    /// the client can purge the hidden principal or wait for the retention period. The error says that the value is
    /// reserved and nothing else about the hidden principal. A conflict refined by [`Precondition::ExternalRefReserved`]
    /// (409 `external-ref-reserved`).
    pub fn external_ref_reserved() -> Self {
        Self::with_message(
            ErrorKind::Conflict,
            SafeMessage::from_static(
                "The external reference belongs to a deleted principal that has not been purged yet.",
            ),
        )
        .with_precondition(Precondition::ExternalRefReserved)
    }

    /// An address of a principal write belongs to a **deleted principal that has not been purged yet**; see
    /// [`AppError::external_ref_reserved`]. A conflict refined by [`Precondition::AddressReserved`] (409
    /// `address-reserved`).
    pub fn address_reserved() -> Self {
        Self::with_message(
            ErrorKind::Conflict,
            SafeMessage::from_static("An address belongs to a deleted principal that has not been purged yet."),
        )
        .with_precondition(Precondition::AddressReserved)
    }

    /// An unexpected failure; `source` is kept for logs and never shown to clients.
    pub fn internal(source: impl StdError + Send + Sync + 'static) -> Self {
        Self::new(ErrorKind::Internal).with_source(source)
    }

    /// Refines the error with a CalDAV/WebDAV precondition.
    #[must_use]
    pub fn with_precondition(mut self, precondition: Precondition) -> Self {
        self.precondition = Some(Box::new(precondition));
        self
    }

    /// Replaces the client-safe message.
    #[must_use]
    pub fn with_public_message(mut self, message: SafeMessage) -> Self {
        self.public_message = message;
        self
    }

    /// Names an invalid field of the request body: the client gets `pointer`, `code` and `message` in the
    /// `errors` list of the problem document. May be called once per wrong field.
    #[must_use]
    pub fn with_field_error(mut self, pointer: &'static str, code: &'static str, message: SafeMessage) -> Self {
        self.field_errors.push(FieldError { pointer, code, message });
        self
    }

    /// Sets how long a rate-limited caller should wait.
    #[must_use]
    pub const fn with_retry_after(mut self, retry_after: Duration) -> Self {
        self.retry_after = Some(retry_after);
        self
    }

    /// Attaches the underlying error for logs and operators.
    #[must_use]
    pub fn with_source(mut self, source: impl StdError + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    /// The coarse class of the failure.
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The precondition that refines the kind, if any.
    pub fn precondition(&self) -> Option<&Precondition> {
        self.precondition.as_deref()
    }

    /// The only text that may be shown to a client.
    pub const fn public_message(&self) -> &SafeMessage {
        &self.public_message
    }

    /// How long a rate-limited caller should wait before repeating the request.
    pub const fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }

    /// The invalid fields of the request body, if the error names any.
    pub fn field_errors(&self) -> &[FieldError] {
        &self.field_errors
    }

    /// The problem document of this error (RFC 9457, PLAN 2.10): the catalog row comes from the precondition when
    /// it has one this release knows and from the kind otherwise ([`ProblemCode::from_error`]), the detail is the
    /// client-safe message unless that is just the generic text of the kind, and the invalid fields are listed.
    /// The source error and every internal text stay out of it. The document carries no request id (the edge adds
    /// it, [`ProblemDetails::with_request_id`]) and the HTTP status of the catalog row (a surface may answer with
    /// another one).
    ///
    /// This is the one translation of an application error into a problem: the edge layers
    /// (`EdgeProblem::from_app_error`), the MCP tool results and the per-item problems of a batch all use it.
    pub fn problem_details(&self) -> ProblemDetails {
        let mut problem = ProblemDetails::new(ProblemCode::from_error(self.kind, self.precondition()));
        if self.public_message != SafeMessage::for_kind(self.kind) {
            problem = problem.with_detail(self.public_message.as_str());
        }
        for field in &self.field_errors {
            problem = problem.with_error(FieldProblem::new(field.pointer, field.code, field.message.as_str()));
        }
        problem
    }
}

impl fmt::Display for AppError {
    /// Formats `kind: public message`. The source error is never part of the output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.public_message)
    }
}

impl StdError for AppError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|source| -> &(dyn StdError + 'static) { source })
    }
}

/// The client-safe description of a violated unique constraint.
const fn unique_violation_message(key: UniqueKey) -> &'static str {
    match key {
        UniqueKey::TenantSlug => "A tenant with this slug already exists.",
        UniqueKey::LoginDomain => "Another tenant already uses this login domain.",
        UniqueKey::PrincipalName => "A principal with this name already exists.",
        UniqueKey::ExternalRef => "A principal with this external reference already exists.",
        UniqueKey::Address => "This address already belongs to another principal.",
        UniqueKey::CalendarSlug => "A calendar with this slug already exists.",
        UniqueKey::BindingSlug => "A calendar with this name already exists in the home.",
        UniqueKey::BindingCalendar => "The calendar is already in the home.",
        UniqueKey::Grant => "The calendar is already shared with this principal.",
        UniqueKey::ObjectUid => "Another resource in the calendar has this UID.",
        UniqueKey::SchedulingUid => "A scheduling object with this UID already exists.",
        UniqueKey::ExternalKey => "An object with this external key already exists.",
        UniqueKey::ObjectUri | UniqueKey::NotificationUri | UniqueKey::InboxUri => {
            "A resource with this name already exists."
        }
        UniqueKey::CredentialPrefix => "The credential could not be created; try again.",
        UniqueKey::IdempotencyKey => "This idempotency key is already in use.",
        UniqueKey::OAuthState => "This authorization is already in progress.",
        _ => "A resource with these values already exists.",
    }
}

impl From<StoreError> for AppError {
    /// The default mapping of storage failures.
    ///
    /// `NotFound` is a 404 (other tenants' rows look the same), unique violations are conflicts with a message
    /// naming the field, a stale version is a failed precondition, an unusable sync token is `Invalid` with
    /// `valid-sync-token` (never the 412 of a stale version), a lost lease is a conflict, text the store cannot
    /// hold is `Invalid`, and everything the caller cannot fix (unavailable, timeout, exhausted serialization
    /// retries, unsupported, internal and any variant a later release adds) hides the cause. A timeout includes
    /// a lock wait that expired behind a busy calendar: use cases may retry it like a serialization failure
    /// (`StoreError::is_retryable`) before they give up with a 503. Use cases that can name the conflicting
    /// resource refine unique violations with the matching precondition.
    fn from(error: StoreError) -> Self {
        let mapped = match &error {
            StoreError::NotFound => Self::not_found(),
            StoreError::UniqueViolation(key) => {
                Self::conflict().with_public_message(SafeMessage::from_static(unique_violation_message(*key)))
            }
            StoreError::PreconditionFailed => Self::precondition_failed(),
            StoreError::InvalidSyncToken => Self::invalid(SafeMessage::from_static(
                "The sync token is no longer valid; start a new sync.",
            ))
            .with_precondition(Precondition::ValidSyncToken),
            StoreError::LeaseLost => Self::conflict(),
            StoreError::InvalidData(_) => Self::invalid(SafeMessage::from_static(
                "A value contains a character that cannot be stored.",
            )),
            StoreError::Unsupported => Self::unsupported(),
            StoreError::SerializationFailure | StoreError::Unavailable | StoreError::Timeout => Self::unavailable(),
            _ => Self::new(ErrorKind::Internal),
        };
        mapped.with_source(error)
    }
}

impl From<PortError> for AppError {
    /// The default mapping of port failures.
    ///
    /// `Unavailable` and `Timeout` are retryable 503s, `Rejected` (a policy refused what the caller asked for)
    /// is an invalid request, `Unsupported` stays unsupported, and `Invalid` (the application built a request the
    /// port cannot accept) and `Internal` are internal errors: the application validates client input itself, so
    /// a port complaining about its input is a bug on our side.
    fn from(error: PortError) -> Self {
        let kind = match error.kind {
            PortErrorKind::Unavailable | PortErrorKind::Timeout => ErrorKind::Unavailable,
            PortErrorKind::Rejected => ErrorKind::Invalid,
            PortErrorKind::Unsupported => ErrorKind::Unsupported,
            PortErrorKind::Invalid | PortErrorKind::Internal => ErrorKind::Internal,
        };
        Self::new(kind).with_source(error)
    }
}

impl AppError {
    /// The error for an iCalendar failure in `context` (`davhaven_ical::ErrorContext`).
    ///
    /// The precondition depends on what the client was doing: invalid data is `CALDAV:valid-calendar-data` when
    /// it stores an object, `CALDAV:valid-filter` when it comes from a query and
    /// `CALDAV:valid-scheduling-message` when it comes from an iTIP message; a violated calendar object resource
    /// rule or an organizer mismatch has its own precondition when storing. Limits map as documented in
    /// [`LimitKind::precondition_in`]. The client sees the text of the rejection; a time budget that ran out is a
    /// transient 503 (never a statement about the data) and unsupported operations are server-side gaps.
    ///
    /// Call this with [`ErrorContext::Query`] for filters, projections, expansion and free-busy and with
    /// [`ErrorContext::Scheduling`] for iTIP messages; `AppError::from` assumes [`ErrorContext::Store`].
    pub fn from_ical(error: IcalError, context: ErrorContext) -> Self {
        let mapped = match &error {
            IcalError::Unsupported(_) => Self::unsupported(),
            IcalError::Limit(LimitKind::TimeBudget) => Self::unavailable().with_public_message(
                SafeMessage::from_static("The request took too long to process; try again later."),
            ),
            IcalError::Limit(LimitKind::ResourceSize) => {
                let mapped = Self::too_large();
                match error.precondition_in(context) {
                    Some(precondition) => mapped.with_precondition(precondition),
                    None => mapped,
                }
            }
            other => {
                let message = other
                    .client_message()
                    .map_or_else(|| SafeMessage::for_kind(ErrorKind::Invalid), SafeMessage::sanitized);
                let mapped = Self::invalid(message.clone());
                match other.precondition_in(context) {
                    Some(Precondition::ValidCalendarData(_)) => {
                        mapped.with_precondition(Precondition::ValidCalendarData(message.as_str().to_owned()))
                    }
                    Some(precondition) => mapped.with_precondition(precondition),
                    None => mapped,
                }
            }
        };
        mapped.with_source(error)
    }
}

impl From<IcalError> for AppError {
    /// The mapping of iCalendar failures of a request that stores data ([`ErrorContext::Store`]); use
    /// [`AppError::from_ical`] for queries and scheduling messages.
    fn from(error: IcalError) -> Self {
        Self::from_ical(error, ErrorContext::Store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_fields_are_named_by_pointer_and_code() {
        let plain = AppError::invalid(SafeMessage::from_static("The request is invalid."));
        assert_eq!(plain.field_errors().len(), 0);
        let error = plain
            .with_field_error(
                "/url",
                "not-allowed",
                SafeMessage::from_static("The URL is not allowed."),
            )
            .with_field_error("/events", "empty", SafeMessage::from_static("Name at least one event."));
        assert_eq!(error.kind(), ErrorKind::Invalid);
        let pointers: Vec<(&str, &str)> = error
            .field_errors()
            .iter()
            .map(|field| (field.pointer, field.code))
            .collect();
        assert_eq!(pointers, vec![("/url", "not-allowed"), ("/events", "empty")]);
        assert_eq!(error.field_errors()[1].message.as_str(), "Name at least one event.");
        assert!(!error.to_string().contains("/url"), "the display form stays one line");
    }

    fn href() -> Href {
        Href::parse("/dav/calendars/acme/anna/work/x.ics").unwrap()
    }

    #[test]
    fn the_error_stays_small_enough_for_result_types() {
        assert!(
            core::mem::size_of::<AppError>() <= 100,
            "{}",
            core::mem::size_of::<AppError>()
        );
    }

    #[test]
    fn every_kind_has_a_distinct_generic_message() {
        let mut messages = std::collections::HashSet::new();
        for kind in ErrorKind::ALL {
            let error = AppError::new(kind);
            assert_eq!(error.kind(), kind);
            assert!(messages.insert(error.public_message().as_str().to_owned()), "{kind}");
            assert_eq!(error.precondition(), None);
            assert_eq!(error.retry_after(), None);
        }
    }

    #[test]
    fn constructors_pick_the_documented_kind() {
        assert_eq!(AppError::unsupported().kind(), ErrorKind::Unsupported);
        assert_eq!(AppError::not_found().kind(), ErrorKind::NotFound);
        assert_eq!(AppError::unauthenticated().kind(), ErrorKind::Unauthenticated);
        assert_eq!(AppError::forbidden().kind(), ErrorKind::Forbidden);
        assert_eq!(AppError::conflict().kind(), ErrorKind::Conflict);
        assert_eq!(AppError::precondition_failed().kind(), ErrorKind::PreconditionFailed);
        assert_eq!(
            AppError::precondition_required().kind(),
            ErrorKind::PreconditionRequired
        );
        assert_eq!(AppError::too_large().kind(), ErrorKind::TooLarge);
        assert_eq!(AppError::unavailable().kind(), ErrorKind::Unavailable);
        let limited = AppError::rate_limited(Duration::from_secs(30));
        assert_eq!(limited.kind(), ErrorKind::RateLimited);
        assert_eq!(limited.retry_after(), Some(Duration::from_secs(30)));
        let invalid = AppError::invalid(SafeMessage::from_static("The name is too long."));
        assert_eq!(invalid.public_message().as_str(), "The name is too long.");
        let denied = AppError::need_privilege(href(), Privilege::WriteContent);
        assert_eq!(denied.kind(), ErrorKind::Forbidden);
        assert_eq!(denied.precondition().map(Precondition::code), Some("need-privileges"));
    }

    #[test]
    fn internal_causes_never_reach_display_or_the_public_message() {
        let secret = "relation \"calendar_objects\" does not exist (password=hunter2)";
        let error = AppError::from(StoreError::internal(secret));
        assert_eq!(error.kind(), ErrorKind::Internal);
        assert!(!error.to_string().contains("hunter2"), "{error}");
        assert!(!error.public_message().as_str().contains("hunter2"));
        let source = StdError::source(&error).expect("the cause is kept for logs");
        assert!(source.to_string().contains("hunter2"));
        let port = AppError::from(PortError::internal("smtp password rejected"));
        assert_ne!(format!("{port} {port:?}"), "");
        assert!(!port.to_string().contains("smtp"));
    }

    #[test]
    fn store_errors_map_to_the_documented_kinds() {
        let cases = [
            (StoreError::NotFound, ErrorKind::NotFound),
            (StoreError::PreconditionFailed, ErrorKind::PreconditionFailed),
            (StoreError::SerializationFailure, ErrorKind::Unavailable),
            (StoreError::Unavailable, ErrorKind::Unavailable),
            (StoreError::Timeout, ErrorKind::Unavailable),
            (StoreError::InvalidSyncToken, ErrorKind::Invalid),
            (StoreError::LeaseLost, ErrorKind::Conflict),
            (StoreError::InvalidData("text".to_owned()), ErrorKind::Invalid),
            (StoreError::Unsupported, ErrorKind::Unsupported),
            (StoreError::internal("boom"), ErrorKind::Internal),
        ];
        for (store, kind) in cases {
            assert_eq!(AppError::from(store.clone()).kind(), kind, "{store}");
        }
        let token = AppError::from(StoreError::InvalidSyncToken);
        assert_eq!(
            token.precondition().map(Precondition::code),
            Some("valid-sync-token"),
            "an unusable sync token is never the 412 of a stale version"
        );
    }

    #[test]
    fn every_unique_key_is_a_conflict_with_its_own_client_safe_message() {
        let mut messages = std::collections::HashSet::new();
        for key in UniqueKey::ALL {
            let error = AppError::from(StoreError::UniqueViolation(key));
            assert_eq!(error.kind(), ErrorKind::Conflict, "{key}");
            assert!(error.public_message().as_str().ends_with('.'), "{key}");
            messages.insert(error.public_message().as_str().to_owned());
        }
        assert!(
            messages.len() >= UniqueKey::ALL.len() - 2,
            "keys share at most their obvious messages"
        );
        let slug = AppError::from(StoreError::UniqueViolation(UniqueKey::CalendarSlug));
        assert!(slug.public_message().as_str().contains("slug"));
    }

    #[test]
    fn port_errors_map_to_the_documented_kinds() {
        let expected = [
            (PortErrorKind::Unavailable, ErrorKind::Unavailable),
            (PortErrorKind::Timeout, ErrorKind::Unavailable),
            (PortErrorKind::Rejected, ErrorKind::Invalid),
            (PortErrorKind::Invalid, ErrorKind::Internal),
            (PortErrorKind::Unsupported, ErrorKind::Unsupported),
            (PortErrorKind::Internal, ErrorKind::Internal),
        ];
        assert_eq!(expected.len(), PortErrorKind::ALL.len());
        for (port_kind, kind) in expected {
            let error = AppError::from(PortError::new(port_kind, "operator text"));
            assert_eq!(error.kind(), kind, "{port_kind}");
            assert!(!error.to_string().contains("operator text"));
        }
        assert_eq!(AppError::from(PortError::unsupported()).kind(), ErrorKind::Unsupported);
    }

    #[test]
    fn ical_errors_become_calendar_data_preconditions() {
        let invalid = AppError::from(IcalError::invalid("DTEND is before DTSTART"));
        assert_eq!(invalid.kind(), ErrorKind::Invalid);
        assert_eq!(invalid.public_message().as_str(), "DTEND is before DTSTART");
        assert_eq!(
            invalid.precondition(),
            Some(&Precondition::ValidCalendarData("DTEND is before DTSTART".to_owned()))
        );
        let unsupported = AppError::from(IcalError::unsupported("COUNTER"));
        assert_eq!(unsupported.kind(), ErrorKind::Unsupported);
        assert_eq!(unsupported.precondition(), None);
        assert!(!unsupported.to_string().contains("COUNTER"));
        for limit in LimitKind::ALL {
            let error = AppError::from(IcalError::Limit(limit));
            let expected_kind = match limit {
                LimitKind::ResourceSize => ErrorKind::TooLarge,
                LimitKind::TimeBudget => ErrorKind::Unavailable,
                _ => ErrorKind::Invalid,
            };
            assert_eq!(error.kind(), expected_kind, "{limit}");
            assert_eq!(
                error.precondition(),
                IcalError::Limit(limit).precondition().as_ref(),
                "{limit}"
            );
        }
    }

    #[test]
    fn the_precondition_depends_on_what_the_client_was_doing() {
        let cases = [
            (
                IcalError::invalid("a value is wrong"),
                ["valid-calendar-data", "valid-filter", "valid-scheduling-message"],
            ),
            (
                IcalError::object_rule("a METHOD"),
                [
                    "valid-calendar-object-resource",
                    "valid-filter",
                    "valid-scheduling-message",
                ],
            ),
            (
                IcalError::organizer_mismatch("two organizers"),
                [
                    "same-organizer-in-all-components",
                    "valid-filter",
                    "valid-scheduling-message",
                ],
            ),
            (
                IcalError::Limit(LimitKind::MaxDateTime),
                ["max-date-time", "valid-filter", "valid-scheduling-message"],
            ),
            (
                IcalError::Limit(LimitKind::Instances),
                ["max-instances", "valid-filter", "valid-scheduling-message"],
            ),
        ];
        for (error, codes) in cases {
            for (context, code) in ErrorContext::ALL.into_iter().zip(codes) {
                let mapped = AppError::from_ical(error.clone(), context);
                assert_eq!(mapped.kind(), ErrorKind::Invalid, "{error} in {context:?}");
                assert_eq!(
                    mapped.precondition().map(Precondition::code),
                    Some(code),
                    "{error} in {context:?}"
                );
            }
        }
        // The text of a rejection reaches the client in every context.
        let shown = AppError::from_ical(IcalError::object_rule("METHOD is not allowed"), ErrorContext::Store);
        assert_eq!(shown.public_message().as_str(), "METHOD is not allowed");
    }

    #[test]
    fn running_out_of_time_is_a_transient_failure_in_every_context() {
        for context in ErrorContext::ALL {
            let mapped = AppError::from_ical(IcalError::Limit(LimitKind::TimeBudget), context);
            assert_eq!(mapped.kind(), ErrorKind::Unavailable, "{context:?}");
            assert_eq!(mapped.precondition(), None, "{context:?}");
        }
    }

    #[test]
    fn sanitized_messages_drop_control_characters_and_cap_their_length() {
        let message = SafeMessage::sanitized("  line one\r\nline\ttwo \u{0}\u{7f} end  ");
        assert_eq!(message.as_str(), "line one line two end");
        let long = SafeMessage::sanitized(&"x".repeat(1000));
        assert_eq!(long.as_str().chars().count(), MAX_SAFE_MESSAGE_CHARS);
        assert_eq!(
            SafeMessage::sanitized("\n\t ").as_str(),
            SafeMessage::for_kind(ErrorKind::Invalid).as_str()
        );
        assert_eq!(SafeMessage::sanitized("Ümlaut stays").as_str(), "Ümlaut stays");
    }

    #[test]
    fn disabled_features_are_conflicts_refined_by_their_own_precondition() {
        use davhaven_wire::ProblemCode;

        let error = AppError::feature_not_enabled();
        assert_eq!(error.kind(), ErrorKind::Conflict);
        assert_eq!(error.precondition(), Some(&Precondition::FeatureNotEnabled));
        assert_eq!(error.public_message().as_str(), "This feature is not enabled.");
        assert_eq!(
            ProblemCode::from_error(error.kind(), error.precondition()),
            ProblemCode::FeatureNotEnabled
        );
        assert_eq!(
            ProblemCode::from_error(ErrorKind::Conflict, None),
            ProblemCode::Conflict
        );
    }

    #[test]
    fn the_problem_of_an_error_is_the_catalog_row_with_only_client_safe_text() {
        // The generic text of a kind is not repeated as a detail, and the source never appears.
        let internal = AppError::internal(std::io::Error::other(
            "relation \"x\" does not exist (password=hunter2)",
        ));
        let problem = internal.problem_details();
        assert_eq!(problem.code, ProblemCode::Internal);
        assert_eq!(problem.detail, None);
        assert_eq!(problem.status, ProblemCode::Internal.http_status());
        assert!(problem.request_id.is_none() && problem.errors.is_empty());
        assert!(!format!("{problem:?}").contains("hunter2"));

        // A specific message becomes the detail; the precondition decides the row; invalid fields are listed.
        let refined = AppError::conflict()
            .with_precondition(Precondition::NoUidConflict(href()))
            .with_public_message(SafeMessage::from_static("The UID is taken."))
            .with_field_error("/uid", "taken", SafeMessage::from_static("This UID exists."));
        let problem = refined.problem_details();
        assert_eq!(problem.code, ProblemCode::UidConflict);
        assert_eq!(problem.detail.as_deref(), Some("The UID is taken."));
        assert_eq!(
            problem.errors,
            vec![FieldProblem::new("/uid", "taken", "This UID exists.")]
        );

        // The same rule for every kind: the document names the row `ProblemCode::from_error` picks.
        for kind in [
            ErrorKind::NotFound,
            ErrorKind::Forbidden,
            ErrorKind::PreconditionFailed,
            ErrorKind::TooLarge,
        ] {
            let error = AppError::new(kind);
            assert_eq!(
                error.problem_details().code,
                ProblemCode::from_error(kind, None),
                "{kind}"
            );
            assert_eq!(error.problem_details().detail, None, "{kind}");
        }
    }

    #[test]
    fn builders_refine_without_losing_the_kind() {
        let error = AppError::conflict()
            .with_precondition(Precondition::NoUidConflict(href()))
            .with_public_message(SafeMessage::from_static("The UID is taken."))
            .with_retry_after(Duration::from_secs(1));
        assert_eq!(error.kind(), ErrorKind::Conflict);
        assert_eq!(error.precondition().and_then(Precondition::href), Some(&href()));
        assert_eq!(error.to_string(), "conflict: The UID is taken.");
        assert_eq!(error.retry_after(), Some(Duration::from_secs(1)));
    }
}
