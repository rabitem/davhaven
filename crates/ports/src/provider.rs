//! Calendar provider ports: `OAuthProvider` and `RemoteCalendarApi`.
//!
//! A provider connects an external calendar service (Google, Microsoft) to a principal: the OAuth flow
//! authorizes access, and the sync engine pulls changes into a mirror calendar through the provider's calendar API.
//! 1.0 is pull-only; the push direction (`upsert`, `delete`) is reserved and providers answer
//! [`PortErrorKind::Unsupported`] for it. All HTTP goes through the `HttpClient` port, so the egress policy
//! applies to providers too.
//!
//! The registry selects providers as a set (`plugins.providers`); [`Provider`] bundles the two capabilities of one
//! provider under its name, together with whether the deployment switched it on.
//!
//! # How a pull works
//!
//! The sync engine calls [`RemoteCalendarApi::changes_since`] with the cursor it stored after the last pull. What the
//! answer means depends on [`RemoteChanges::snapshot`]: a **delta** lists the events that changed (and the ones that
//! were deleted, with `ics: None`) since the cursor, and a **snapshot** lists every event of the calendar **within the window
//! the adapter reads** (the providers of 1.0 read a window around the time of the call, `history_days` before and
//! `future_days` after it), so the engine deletes what it still holds and the snapshot does not list: an event that leaves
//! the window leaves the mirror. A provider with a change feed answers deltas; one without (the providers of 1.0 list the
//! window again on every pull) answers snapshots, and the engine handles both.
//!
//! # What an error of a pull means
//!
//! The engine reacts to the kind of the [`PortError`], and only to the kind:
//!
//! * [`PortErrorKind::Rejected`] from [`OAuthProvider::refresh`] is **only** "the refresh token is no longer valid" (RFC 6749
//!   section 5.2 `invalid_grant`: the person removed the access, or it expired or was revoked). It switches the account off,
//!   because only a new consent helps. From [`RemoteCalendarApi`] it is "the access token or the calendar is refused": the
//!   engine renews the token once and asks again.
//! * [`PortErrorKind::Invalid`] from `refresh` or `exchange` is "the provider refuses the **client** of the deployment" (RFC
//!   6749 `invalid_client`, `unauthorized_client`, `invalid_request`, `invalid_scope`: a wrong, rotated or expired client
//!   secret). That is a fault of the deployment and of no account: the account stays on and is tried again after the backoff,
//!   and recovers by itself once the operator has fixed the client.
//! * [`PortErrorKind::Unsupported`] from [`RemoteCalendarApi::changes_since`] is "the calendar is beyond what the adapter
//!   imports" (more events in the window than it reads). A new token does not help, so the engine does not renew.
//! * [`PortErrorKind::Unavailable`] and [`PortErrorKind::Timeout`] are faults of the moment.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use secrecy::SecretString;
use url::Url;

use crate::error::{PortError, PortErrorKind};

/// OAuth tokens of a connected account.
#[derive(Debug, Clone)]
pub struct OAuthTokens {
    /// The access token for provider API calls.
    pub access_token: SecretString,
    /// The refresh token, when the provider issues one.
    pub refresh_token: Option<SecretString>,
    /// When the access token expires.
    pub expires_at: Option<DateTime<Utc>>,
    /// The scopes the provider granted, space separated.
    pub scope: Option<String>,
}

/// The result of a successful code exchange.
#[derive(Debug, Clone)]
pub struct OAuthGrant {
    /// The tokens.
    pub tokens: OAuthTokens,
    /// The provider's reference for the connected account (stored as `external_accounts.account_ref`).
    pub account_ref: String,
}

/// The OAuth 2.0 authorization code flow with PKCE of one provider.
#[async_trait]
pub trait OAuthProvider: Send + Sync {
    /// The URL the user is sent to for consent. `state` is the single-use state value, `pkce_challenge` the
    /// S256 code challenge and `redirect` the callback URL of the deployment (`{public base URL}/oauth/{name}/callback`,
    /// which `providers.<name>.redirect_uri` must equal: `davhaven config check` compares the two).
    ///
    /// # Errors
    ///
    /// `Invalid` when the provider is not configured completely.
    fn authorize_url(&self, state: &str, pkce_challenge: &str, redirect: &Url) -> Result<Url, PortError>;

    /// Exchanges the authorization `code` and the PKCE `verifier` for tokens.
    ///
    /// # Errors
    ///
    /// `Rejected` when the provider refuses the code (`invalid_grant`), `Invalid` when it refuses the client of the
    /// deployment (`invalid_client` and the other errors of the client), `Unavailable` and `Timeout` for transport
    /// failures.
    async fn exchange(
        &self,
        code: &SecretString,
        verifier: &SecretString,
        redirect: &Url,
    ) -> Result<OAuthGrant, PortError>;

    /// Obtains a new access token with a refresh token.
    ///
    /// # Errors
    ///
    /// `Rejected` **only** when the provider says that the refresh token is no longer valid (`invalid_grant`: the person
    /// removed the access, or it was revoked or expired), so that the account must be connected again. `Invalid` when the
    /// provider refuses the client of the deployment (`invalid_client`, `unauthorized_client`, `invalid_request`,
    /// `invalid_scope`; an expired or rotated client secret): that is no fault of the account, and a new consent would not
    /// help. `Unavailable` and `Timeout` for transport failures and throttling.
    async fn refresh(&self, refresh_token: &SecretString) -> Result<OAuthTokens, PortError>;

    /// Revokes a token at the provider (best effort when an account is disconnected).
    ///
    /// # Errors
    ///
    /// Transport failures; callers log and continue.
    async fn revoke(&self, token: &SecretString) -> Result<(), PortError>;
}

/// A calendar of the remote account.
///
/// The struct is `#[non_exhaustive]`: build it with [`RemoteCalendar::new`], so that a member added later does not break
/// an adapter.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCalendar {
    /// The provider's id of the calendar.
    pub remote_id: String,
    /// The calendar's display name.
    pub display_name: String,
    /// The calendar color as `#RRGGBB`, when the provider has one.
    pub color: Option<String>,
    /// Whether this is the main calendar of the account (the one the sync engine mirrors).
    pub primary: bool,
}

impl RemoteCalendar {
    /// A calendar that is not the primary one and has no color.
    pub fn new(remote_id: impl Into<String>, display_name: impl Into<String>) -> Self {
        Self {
            remote_id: remote_id.into(),
            display_name: display_name.into(),
            color: None,
            primary: false,
        }
    }

    /// Sets the color (`#RRGGBB`).
    #[must_use]
    pub fn with_color(mut self, color: impl Into<String>) -> Self {
        self.color = Some(color.into());
        self
    }

    /// Marks the calendar as the primary one of the account.
    #[must_use]
    pub const fn primary(mut self) -> Self {
        self.primary = true;
        self
    }
}

/// One changed event of a remote calendar.
#[derive(Clone, PartialEq, Eq)]
pub struct RemoteChange {
    /// The provider's id of the event.
    pub remote_id: String,
    /// The provider's entity tag of the event, when it has one.
    pub etag: Option<String>,
    /// The event as iCalendar text; `None` means the event was deleted remotely.
    pub ics: Option<String>,
}

impl core::fmt::Debug for RemoteChange {
    /// Omits the iCalendar text, which holds event content.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RemoteChange")
            .field("remote_id", &self.remote_id)
            .field("etag", &self.etag)
            .field("deleted", &self.ics.is_none())
            .finish()
    }
}

/// The changes of a remote calendar since a cursor.
///
/// The struct is `#[non_exhaustive]`: build it with [`RemoteChanges::delta`] or [`RemoteChanges::snapshot`].
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteChanges {
    /// The events: the changed ones and, for a delta, the deleted ones (`ics: None`); for a snapshot every event within
    /// the window the adapter reads.
    pub changes: Vec<RemoteChange>,
    /// The cursor to pass next time (a sync token of the provider, or a time stamp for a provider that has none). The
    /// caller stores it in `external_accounts.sync_state` only after it applied `changes`.
    pub cursor: String,
    /// Whether `changes` is the complete list of the calendar's events **within the window the adapter reads** instead of
    /// a difference: whatever the mirror holds and the list does not name was deleted remotely or left the window.
    pub snapshot: bool,
}

impl RemoteChanges {
    /// A difference: the events that changed or were deleted since the cursor.
    pub fn delta(changes: Vec<RemoteChange>, cursor: impl Into<String>) -> Self {
        Self {
            changes,
            cursor: cursor.into(),
            snapshot: false,
        }
    }

    /// The complete list of the events of the calendar within the window the adapter reads.
    pub fn snapshot(changes: Vec<RemoteChange>, cursor: impl Into<String>) -> Self {
        Self {
            changes,
            cursor: cursor.into(),
            snapshot: true,
        }
    }
}

/// Reads (and, later, writes) the calendars of a connected remote account.
#[async_trait]
pub trait RemoteCalendarApi: Send + Sync {
    /// Lists the calendars of the account.
    ///
    /// # Errors
    ///
    /// `Rejected` for an invalid or revoked token, `Unavailable` and `Timeout` for transport failures.
    async fn list_calendars(&self, token: &SecretString) -> Result<Vec<RemoteCalendar>, PortError>;

    /// Lists the events that changed in `calendar` since `cursor`; without a cursor, all events (initial sync).
    ///
    /// # Errors
    ///
    /// `Invalid` when the provider no longer accepts the cursor (the caller restarts with a full sync), `Unsupported` when
    /// the calendar is beyond what the adapter imports (more events in the window than it reads; renewing the token does
    /// not help), and the errors of [`RemoteCalendarApi::list_calendars`].
    async fn changes_since(
        &self,
        token: &SecretString,
        calendar: &str,
        cursor: Option<&str>,
    ) -> Result<RemoteChanges, PortError>;

    /// Creates or replaces an event remotely (push direction, reserved for a later release).
    ///
    /// The default answers [`PortErrorKind::Unsupported`]: providers are pull-only in 1.0.
    ///
    /// # Errors
    ///
    /// `Unsupported` unless the provider implements the push direction.
    async fn upsert(
        &self,
        _token: &SecretString,
        _calendar: &str,
        _change: &RemoteChange,
    ) -> Result<RemoteChange, PortError> {
        Err(PortError::new(
            PortErrorKind::Unsupported,
            "this provider does not support writing to the remote calendar",
        ))
    }

    /// Deletes an event remotely (push direction, reserved for a later release).
    ///
    /// The default answers [`PortErrorKind::Unsupported`].
    ///
    /// # Errors
    ///
    /// `Unsupported` unless the provider implements the push direction.
    async fn delete(&self, _token: &SecretString, _calendar: &str, _remote_id: &str) -> Result<(), PortError> {
        Err(PortError::new(
            PortErrorKind::Unsupported,
            "this provider does not support deleting from the remote calendar",
        ))
    }
}

/// A provider plugin: its name, its OAuth flow and its calendar API.
pub trait Provider: Send + Sync {
    /// The provider name used in URLs and configuration (`google`, `microsoft`, `fake`).
    fn name(&self) -> &'static str;

    /// The name people know the provider by (`Google`), for pages and for the names of mirror calendars. The default is
    /// [`name`](Self::name).
    fn display_name(&self) -> &'static str {
        self.name()
    }

    /// Whether the deployment switched the provider on (`providers.<name>.enabled`). A provider that is selected but off
    /// answers 409 `feature-not-enabled` on the management API, and its accounts are not synchronized. The default is
    /// `true`: a plugin without a switch is on whenever it is selected.
    fn enabled(&self) -> bool {
        true
    }

    /// The OAuth flow of the provider.
    fn oauth(&self) -> &dyn OAuthProvider;

    /// The calendar API of the provider.
    fn calendars(&self) -> &dyn RemoteCalendarApi;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PullOnly;

    #[async_trait]
    impl RemoteCalendarApi for PullOnly {
        async fn list_calendars(&self, _token: &SecretString) -> Result<Vec<RemoteCalendar>, PortError> {
            Ok(Vec::new())
        }

        async fn changes_since(
            &self,
            _token: &SecretString,
            _calendar: &str,
            _cursor: Option<&str>,
        ) -> Result<RemoteChanges, PortError> {
            Ok(RemoteChanges::delta(Vec::new(), "c1"))
        }
    }

    #[tokio::test]
    async fn providers_are_pull_only_by_default() {
        let api = PullOnly;
        let token = SecretString::from("token");
        let change = RemoteChange {
            remote_id: "e1".to_owned(),
            etag: None,
            ics: Some("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n".to_owned()),
        };
        let upsert = api.upsert(&token, "cal", &change).await.unwrap_err();
        assert_eq!(upsert.kind, PortErrorKind::Unsupported);
        let delete = api.delete(&token, "cal", "e1").await.unwrap_err();
        assert_eq!(delete.kind, PortErrorKind::Unsupported);
        assert_eq!(api.changes_since(&token, "cal", None).await.unwrap().cursor, "c1");
    }

    #[test]
    fn calendars_and_changes_are_built_with_their_constructors() {
        let calendar = RemoteCalendar::new("primary", "Anna").with_color("#336699").primary();
        assert!(calendar.primary);
        assert_eq!(calendar.color.as_deref(), Some("#336699"));
        assert!(!RemoteCalendar::new("other", "Other").primary);
        let delta = RemoteChanges::delta(Vec::new(), "t1");
        let snapshot = RemoteChanges::snapshot(Vec::new(), "t2");
        assert!(!delta.snapshot && snapshot.snapshot);
        assert_eq!((delta.cursor.as_str(), snapshot.cursor.as_str()), ("t1", "t2"));
    }

    struct Plain;

    impl Provider for Plain {
        fn name(&self) -> &'static str {
            "plain"
        }

        fn oauth(&self) -> &dyn OAuthProvider {
            unreachable_oauth()
        }

        fn calendars(&self) -> &dyn RemoteCalendarApi {
            &PullOnly
        }
    }

    /// The OAuth half is never asked for in this test.
    fn unreachable_oauth() -> &'static dyn OAuthProvider {
        struct Never;
        #[async_trait]
        impl OAuthProvider for Never {
            fn authorize_url(&self, _state: &str, _challenge: &str, _redirect: &Url) -> Result<Url, PortError> {
                Err(PortError::unsupported())
            }

            async fn exchange(
                &self,
                _code: &SecretString,
                _verifier: &SecretString,
                _redirect: &Url,
            ) -> Result<OAuthGrant, PortError> {
                Err(PortError::unsupported())
            }

            async fn refresh(&self, _refresh_token: &SecretString) -> Result<OAuthTokens, PortError> {
                Err(PortError::unsupported())
            }

            async fn revoke(&self, _token: &SecretString) -> Result<(), PortError> {
                Err(PortError::unsupported())
            }
        }
        &Never
    }

    #[test]
    fn a_provider_is_on_and_named_after_its_name_unless_it_says_otherwise() {
        let provider = Plain;
        assert!(provider.enabled());
        assert_eq!(provider.display_name(), "plain");
        assert_eq!(provider.name(), "plain");
    }

    #[test]
    fn remote_changes_and_tokens_do_not_debug_print_content() {
        let change = RemoteChange {
            remote_id: "e1".to_owned(),
            etag: Some("\"1\"".to_owned()),
            ics: Some("SUMMARY:Private appointment".to_owned()),
        };
        let shown = format!("{change:?}");
        assert!(!shown.contains("Private"), "{shown}");
        assert!(shown.contains("deleted: false"), "{shown}");
        let tokens = OAuthTokens {
            access_token: SecretString::from("ya29.secret"),
            refresh_token: Some(SecretString::from("1//refresh")),
            expires_at: None,
            scope: None,
        };
        let shown = format!("{tokens:?}");
        assert!(!shown.contains("ya29") && !shown.contains("1//"), "{shown}");
    }
}
