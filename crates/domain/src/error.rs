//! Error kinds shared by all layers and the CalDAV/WebDAV precondition catalog.
//!
//! [`ErrorKind`] is the coarse classification every layer agrees on; protocol crates map it (together with an
//! optional [`Precondition`]) exactly once to DAV statuses, RFC 9457 problems or MCP results. Internal error text
//! never reaches a client, so neither type carries any.

use core::fmt;

use crate::authz::Privilege;
use crate::path::Href;

/// The class of a failure, independent of the protocol that reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ErrorKind {
    /// The resource does not exist or is invisible to the caller, including other tenants' resources (404).
    NotFound,
    /// The caller did not authenticate or the credential is not valid (401).
    Unauthenticated,
    /// The caller may see the resource but is not permitted to do this (403).
    Forbidden,
    /// The request conflicts with the current state, for example a unique violation (409).
    Conflict,
    /// A conditional request header or version check failed (412).
    PreconditionFailed,
    /// The request must be conditional but is not, for example a calendar delete without `If-Match` (428).
    PreconditionRequired,
    /// The request is malformed or violates a validation rule (400/422, or 403 with a precondition element).
    Invalid,
    /// The request or a value exceeds a size limit (413).
    TooLarge,
    /// The caller exceeded a rate limit (429).
    RateLimited,
    /// A dependency is unavailable or timed out; the request may be retried (503).
    Unavailable,
    /// The operation is not supported, or not implemented yet (501).
    Unsupported,
    /// An unexpected internal failure (500).
    Internal,
}

impl ErrorKind {
    /// Every kind, in declaration order (for exhaustive mapping tests).
    pub const ALL: [Self; 12] = [
        Self::NotFound,
        Self::Unauthenticated,
        Self::Forbidden,
        Self::Conflict,
        Self::PreconditionFailed,
        Self::PreconditionRequired,
        Self::Invalid,
        Self::TooLarge,
        Self::RateLimited,
        Self::Unavailable,
        Self::Unsupported,
        Self::Internal,
    ];

    /// A stable lowercase name for logs and metrics labels.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::Unauthenticated => "unauthenticated",
            Self::Forbidden => "forbidden",
            Self::Conflict => "conflict",
            Self::PreconditionFailed => "precondition_failed",
            Self::PreconditionRequired => "precondition_required",
            Self::Invalid => "invalid",
            Self::TooLarge => "too_large",
            Self::RateLimited => "rate_limited",
            Self::Unavailable => "unavailable",
            Self::Unsupported => "unsupported",
            Self::Internal => "internal",
        }
    }

    /// Whether the failure is caused by the request rather than by the server.
    pub const fn is_client_error(self) -> bool {
        !matches!(self, Self::Unavailable | Self::Unsupported | Self::Internal)
    }

    /// Whether repeating the identical request may succeed later.
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::RateLimited | Self::Unavailable)
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A violated CalDAV/WebDAV precondition or postcondition, reported as an XML element in DAV error bodies
/// (`DAV:need-privileges`, `CALDAV:valid-calendar-data`, ...) and as a problem code by the API.
///
/// New preconditions are added over time, so the enum is `#[non_exhaustive]`; mapping tables match the known
/// variants exhaustively and handle the rest with a generic fallback.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Precondition {
    /// `DAV:need-privileges`: the listed resources need the listed privileges.
    NeedPrivileges(Vec<(Href, Privilege)>),
    /// `CALDAV:valid-calendar-data`: the data is not valid iCalendar or violates a limit; the text is a short,
    /// client-safe explanation.
    ValidCalendarData(String),
    /// `CALDAV:valid-calendar-object-resource`: the data breaks the rules for calendar object resources.
    ValidCalendarObjectResource,
    /// `CALDAV:supported-calendar-component`: the collection does not accept this component type.
    SupportedCalendarComponent,
    /// `CALDAV:supported-calendar-data`: the content type is not `text/calendar`.
    SupportedCalendarData,
    /// `CALDAV:no-uid-conflict`: another resource in the calendar has the UID; the href names it.
    NoUidConflict(Href),
    /// `CALDAV:max-resource-size`: the resource is larger than the limit.
    MaxResourceSize,
    /// `CALDAV:min-date-time`: a date is before the minimum.
    MinDateTime,
    /// `CALDAV:max-date-time`: a date is after the maximum.
    MaxDateTime,
    /// `CALDAV:max-instances`: the recurrence set has too many instances.
    MaxInstances,
    /// `CALDAV:max-attendees-per-instance`: too many attendees.
    MaxAttendeesPerInstance,
    /// `CALDAV:unique-scheduling-object-resource`: the owner already has a scheduling object with this UID.
    UniqueSchedulingObjectResource(Href),
    /// `CALDAV:same-organizer-in-all-components`: components disagree on the organizer.
    SameOrganizerInAllComponents,
    /// `CALDAV:organizer-allowed`: the actor may not create a meeting with this organizer.
    OrganizerAllowed,
    /// `CALDAV:allowed-organizer-scheduling-object-change`: an organizer change that is not allowed.
    AllowedOrganizerSchedulingObjectChange,
    /// `CALDAV:allowed-attendee-scheduling-object-change`: an attendee changed more than their own copy.
    AllowedAttendeeSchedulingObjectChange,
    /// `CALDAV:valid-scheduling-message`: the iTIP message is not valid.
    ValidSchedulingMessage,
    /// `DAV:valid-sync-token`: the sync token is foreign, garbled, from another epoch, or pruned.
    ValidSyncToken,
    /// `DAV:number-of-matches-within-limits`: the query matches too many resources.
    NumberOfMatchesWithinLimits,
    /// `DAV:propfind-finite-depth`: `Depth: infinity` is refused.
    PropfindFiniteDepth,
    /// `CALDAV:valid-filter`: the query filter is invalid or exceeds a limit.
    ValidFilter,
    /// `DAV:resource-must-be-null`: the target of MKCALENDAR/MKCOL already exists.
    ResourceMustBeNull,
    /// `DAV:cannot-modify-protected-property`: a protected property cannot be changed.
    CannotModifyProtectedProperty,
    /// Sharing is not allowed for this calendar or tenant.
    SharingNotAllowed,
    /// The sharee is not a valid target (for example external); the href names it.
    InvalidSharee(Href),
    /// The feature is switched off for the tenant or the deployment (the management API answers 409
    /// `feature-not-enabled`, DAV 403).
    FeatureNotEnabled,
    /// The name belongs to a deleted principal that has not been purged yet (the management API answers 409
    /// `name-reserved` to a write without `If-None-Match: *`, which answers 412): purge the principal or wait for the
    /// retention period.
    NameReserved,
    /// The external reference belongs to a deleted principal that has not been purged yet (the management API
    /// answers 409 `external-ref-reserved`): purge the principal or wait for the retention period.
    ExternalRefReserved,
    /// An address belongs to a deleted principal that has not been purged yet (the management API answers 409
    /// `address-reserved`): purge the principal or wait for the retention period.
    AddressReserved,
}

impl Precondition {
    /// The stable kebab-case name of the precondition (the XML element's local name for the DAV ones, for
    /// example `need-privileges`). It carries no payload and is safe for logs and metrics.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NeedPrivileges(_) => "need-privileges",
            Self::ValidCalendarData(_) => "valid-calendar-data",
            Self::ValidCalendarObjectResource => "valid-calendar-object-resource",
            Self::SupportedCalendarComponent => "supported-calendar-component",
            Self::SupportedCalendarData => "supported-calendar-data",
            Self::NoUidConflict(_) => "no-uid-conflict",
            Self::MaxResourceSize => "max-resource-size",
            Self::MinDateTime => "min-date-time",
            Self::MaxDateTime => "max-date-time",
            Self::MaxInstances => "max-instances",
            Self::MaxAttendeesPerInstance => "max-attendees-per-instance",
            Self::UniqueSchedulingObjectResource(_) => "unique-scheduling-object-resource",
            Self::SameOrganizerInAllComponents => "same-organizer-in-all-components",
            Self::OrganizerAllowed => "organizer-allowed",
            Self::AllowedOrganizerSchedulingObjectChange => "allowed-organizer-scheduling-object-change",
            Self::AllowedAttendeeSchedulingObjectChange => "allowed-attendee-scheduling-object-change",
            Self::ValidSchedulingMessage => "valid-scheduling-message",
            Self::ValidSyncToken => "valid-sync-token",
            Self::NumberOfMatchesWithinLimits => "number-of-matches-within-limits",
            Self::PropfindFiniteDepth => "propfind-finite-depth",
            Self::ValidFilter => "valid-filter",
            Self::ResourceMustBeNull => "resource-must-be-null",
            Self::CannotModifyProtectedProperty => "cannot-modify-protected-property",
            Self::SharingNotAllowed => "sharing-not-allowed",
            Self::InvalidSharee(_) => "invalid-sharee",
            Self::FeatureNotEnabled => "feature-not-enabled",
            Self::NameReserved => "name-reserved",
            Self::ExternalRefReserved => "external-ref-reserved",
            Self::AddressReserved => "address-reserved",
        }
    }

    /// The single href the precondition points at (`no-uid-conflict`, `unique-scheduling-object-resource`,
    /// `invalid-sharee`), if it has one.
    pub fn href(&self) -> Option<&Href> {
        match self {
            Self::NoUidConflict(href) | Self::UniqueSchedulingObjectResource(href) | Self::InvalidSharee(href) => {
                Some(href)
            }
            _ => None,
        }
    }

    /// A precondition that asks for one privilege on one resource.
    pub fn need_privilege(href: Href, privilege: Privilege) -> Self {
        Self::NeedPrivileges(vec![(href, privilege)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn href(path: &str) -> Href {
        Href::parse(path).unwrap()
    }

    fn all_preconditions() -> Vec<Precondition> {
        vec![
            Precondition::NeedPrivileges(vec![(href("/dav/calendars/acme/anna/p/"), Privilege::WriteContent)]),
            Precondition::ValidCalendarData("bad".to_owned()),
            Precondition::ValidCalendarObjectResource,
            Precondition::SupportedCalendarComponent,
            Precondition::SupportedCalendarData,
            Precondition::NoUidConflict(href("/dav/calendars/acme/anna/p/a.ics")),
            Precondition::MaxResourceSize,
            Precondition::MinDateTime,
            Precondition::MaxDateTime,
            Precondition::MaxInstances,
            Precondition::MaxAttendeesPerInstance,
            Precondition::UniqueSchedulingObjectResource(href("/dav/calendars/acme/anna/p/b.ics")),
            Precondition::SameOrganizerInAllComponents,
            Precondition::OrganizerAllowed,
            Precondition::AllowedOrganizerSchedulingObjectChange,
            Precondition::AllowedAttendeeSchedulingObjectChange,
            Precondition::ValidSchedulingMessage,
            Precondition::ValidSyncToken,
            Precondition::NumberOfMatchesWithinLimits,
            Precondition::PropfindFiniteDepth,
            Precondition::ValidFilter,
            Precondition::ResourceMustBeNull,
            Precondition::CannotModifyProtectedProperty,
            Precondition::SharingNotAllowed,
            Precondition::InvalidSharee(href("/dav/principals/other/x/")),
            Precondition::FeatureNotEnabled,
            Precondition::NameReserved,
            Precondition::ExternalRefReserved,
            Precondition::AddressReserved,
        ]
    }

    #[test]
    fn codes_are_unique_kebab_case() {
        let preconditions = all_preconditions();
        assert_eq!(
            preconditions.len(),
            29,
            "the plan lists 25 preconditions and the catalog adds feature-not-enabled and the three reservations of deleted principals"
        );
        let mut seen = std::collections::BTreeSet::new();
        for precondition in &preconditions {
            let code = precondition.code();
            assert!(
                !code.is_empty() && code.bytes().all(|b| b.is_ascii_lowercase() || b == b'-') && !code.starts_with('-'),
                "{code}"
            );
            assert!(seen.insert(code), "duplicate code {code}");
        }
    }

    #[test]
    fn only_three_preconditions_point_at_an_href() {
        let with_href: Vec<&str> = all_preconditions()
            .iter()
            .filter(|p| p.href().is_some())
            .map(Precondition::code)
            .collect();
        assert_eq!(
            with_href,
            vec!["no-uid-conflict", "unique-scheduling-object-resource", "invalid-sharee"]
        );
        let conflict = Precondition::NoUidConflict(href("/x"));
        assert_eq!(conflict.href().unwrap().as_str(), "/x");
    }

    #[test]
    fn need_privilege_builds_a_single_pair() {
        let precondition = Precondition::need_privilege(href("/dav/a/"), Privilege::Share);
        assert_eq!(
            precondition,
            Precondition::NeedPrivileges(vec![(href("/dav/a/"), Privilege::Share)])
        );
        assert_eq!(precondition.code(), "need-privileges");
    }

    #[test]
    fn error_kinds_are_exhaustive_and_classified() {
        assert_eq!(ErrorKind::ALL.len(), 12);
        let mut names = std::collections::BTreeSet::new();
        for kind in ErrorKind::ALL {
            assert!(names.insert(kind.as_str()));
            assert_eq!(kind.to_string(), kind.as_str());
        }
        for kind in [ErrorKind::Unavailable, ErrorKind::Unsupported, ErrorKind::Internal] {
            assert!(!kind.is_client_error(), "{kind}");
        }
        for kind in [
            ErrorKind::NotFound,
            ErrorKind::Forbidden,
            ErrorKind::Invalid,
            ErrorKind::RateLimited,
        ] {
            assert!(kind.is_client_error(), "{kind}");
        }
        assert!(ErrorKind::RateLimited.is_retryable());
        assert!(ErrorKind::Unavailable.is_retryable());
        assert!(!ErrorKind::Conflict.is_retryable());
        assert!(!ErrorKind::Internal.is_retryable());
    }
}
