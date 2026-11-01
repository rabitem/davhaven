//! The `Authenticator` port used as an ordered chain.
//!
//! The application's `AuthService` presents the credential of a request to each configured authenticator in order.
//! An authenticator answers [`AuthOutcome::NotApplicable`] when the credential is not one of its kinds, so the next
//! one gets a turn; the first `Accepted` or `Rejected` answer ends the chain. The built-in `auth-local` adapter
//! handles app passwords, API tokens, feed tokens and RSVP tokens; a token introspection authenticator can join
//! the chain later without changing callers.

use core::fmt;
use std::net::IpAddr;

use async_trait::async_trait;
use davhaven_domain::{Actor, Channel, CredentialKind, CredentialRef, RequestId, ScopeSet, TenantId, TenantSlug};
use secrecy::SecretString;

use crate::error::PortError;

/// A credential as presented by a client, before verification.
///
/// `Debug` never prints secrets or the login name.
pub enum PresentedCredential {
    /// HTTP Basic: the login (`name@login_domain` or the bare name) and the app password.
    Basic {
        /// The login name from the `Authorization` header.
        username: String,
        /// The app password.
        password: SecretString,
    },
    /// An API token from a `Bearer` header.
    Bearer(SecretString),
    /// A feed token from a feed URL.
    Feed(SecretString),
    /// An RSVP token from an RSVP link.
    Rsvp(SecretString),
}

impl PresentedCredential {
    /// The kind of credential this presentation would have to be.
    pub const fn kind(&self) -> CredentialKind {
        match self {
            Self::Basic { .. } => CredentialKind::AppPassword,
            Self::Bearer(_) => CredentialKind::ApiToken,
            Self::Feed(_) => CredentialKind::FeedToken,
            Self::Rsvp(_) => CredentialKind::RsvpToken,
        }
    }
}

impl fmt::Debug for PresentedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Basic { .. } => f.write_str("PresentedCredential::Basic { <redacted> }"),
            Self::Bearer(_) => f.write_str("PresentedCredential::Bearer(<redacted>)"),
            Self::Feed(_) => f.write_str("PresentedCredential::Feed(<redacted>)"),
            Self::Rsvp(_) => f.write_str("PresentedCredential::Rsvp(<redacted>)"),
        }
    }
}

/// What an authenticator may use besides the credential itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthHint {
    /// The surface the request arrived on; credentials are bound to their surface.
    pub channel: Channel,
    /// The tenant named by the request path or host, when it names one.
    pub tenant_hint: Option<TenantSlug>,
    /// The client address after trusted-proxy processing.
    pub client_ip: Option<IpAddr>,
    /// The id of the request, for logs.
    pub request_id: RequestId,
}

/// The identity an authenticator established.
#[derive(Debug, Clone, PartialEq)]
pub struct Authenticated {
    /// The tenant of the credential; `None` for system tokens, which are not bound to a tenant.
    pub tenant: Option<TenantId>,
    /// Who acts.
    pub actor: Actor,
    /// The scopes the credential carries (empty for credentials that have none).
    pub scopes: ScopeSet,
    /// The credential that was verified.
    pub credential: CredentialRef,
    /// The label of the credential (token label, app password device name), for audit records.
    pub label: Option<String>,
}

/// Why a credential was refused. The values double as the `reason` label of `auth_failures_total`; clients see the
/// same answer for all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RejectReason {
    /// No credential with this prefix exists.
    UnknownCredential,
    /// The secret does not match.
    BadSecret,
    /// The credential was revoked.
    Revoked,
    /// The credential has expired.
    Expired,
    /// The principal or the tenant is suspended or deleted.
    Suspended,
    /// The credential is valid but not accepted on this surface.
    WrongSurface,
    /// The presented value is malformed (wrong format or length).
    Malformed,
}

impl RejectReason {
    /// Every reason, in declaration order.
    pub const ALL: [Self; 7] = [
        Self::UnknownCredential,
        Self::BadSecret,
        Self::Revoked,
        Self::Expired,
        Self::Suspended,
        Self::WrongSurface,
        Self::Malformed,
    ];

    /// The `snake_case` metric label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownCredential => "unknown_credential",
            Self::BadSecret => "bad_secret",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Suspended => "suspended",
            Self::WrongSurface => "wrong_surface",
            Self::Malformed => "malformed",
        }
    }
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

/// The answer of one authenticator.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthOutcome {
    /// The credential is valid.
    Accepted(Authenticated),
    /// The credential is of this authenticator's kind and invalid. The chain stops.
    Rejected(RejectReason),
    /// The credential is not of this authenticator's kind; the next authenticator tries.
    NotApplicable,
}

/// Verifies presented credentials.
#[async_trait]
pub trait Authenticator: Send + Sync {
    /// Verifies `credential`.
    ///
    /// Unknown credentials cost as much as wrong ones (an equal-cost dummy verification), so response time does
    /// not reveal which prefixes exist.
    ///
    /// # Errors
    ///
    /// Only infrastructure failures (the store is unavailable) are errors; invalid credentials are
    /// [`AuthOutcome::Rejected`].
    async fn authenticate(&self, credential: &PresentedCredential, hint: &AuthHint) -> Result<AuthOutcome, PortError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_map_to_their_kind_and_never_debug_print_secrets() {
        let basic = PresentedCredential::Basic {
            username: "anna@example.org".to_owned(),
            password: SecretString::from("abcd-efgh-ijkl"),
        };
        let cases = [
            (basic, CredentialKind::AppPassword),
            (
                PresentedCredential::Bearer(SecretString::from("dvh_pat_secret")),
                CredentialKind::ApiToken,
            ),
            (
                PresentedCredential::Feed(SecretString::from("dvh_feed_secret")),
                CredentialKind::FeedToken,
            ),
            (
                PresentedCredential::Rsvp(SecretString::from("dvh_rsvp_secret")),
                CredentialKind::RsvpToken,
            ),
        ];
        for (credential, kind) in cases {
            assert_eq!(credential.kind(), kind);
            let shown = format!("{credential:?}");
            assert!(shown.contains("redacted"), "{shown}");
            for secret in ["anna", "abcd", "dvh_"] {
                assert!(!shown.contains(secret), "{shown}");
            }
        }
    }

    #[test]
    fn reject_reasons_have_distinct_labels() {
        let mut labels: Vec<&str> = RejectReason::ALL.iter().map(|reason| reason.as_str()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), RejectReason::ALL.len());
        assert_eq!(RejectReason::BadSecret.to_string(), "bad_secret");
    }
}
