//! What the engine remembers about an account between two pulls, and the ways a pull can fail.
//!
//! The memory is the `sync_state` document of the account (`external_accounts.sync_state`): the remote calendar that is
//! mirrored, the cursor the provider gave at the last pull, when the next pull is due, until when a worker holds the account
//! and how many pulls failed in a row. A document that cannot be read is an account that has not been pulled yet.

use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use davhaven_domain::ExternalAccountStatus;
use davhaven_ports::{PortError, PortErrorKind};
use serde::{Deserialize, Serialize};

/// The `sync_state` document of an account.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SyncState {
    /// The id of the remote calendar that is mirrored (the primary calendar of the account).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) calendar: Option<String>,
    /// The cursor of the provider after the last pull that was applied completely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cursor: Option<String>,
    /// When the next pull is due; an account without it is due at once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) next_sync_at: Option<DateTime<Utc>>,
    /// Until when a worker holds the account: another worker leaves it alone before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) lease_until: Option<DateTime<Utc>>,
    /// When the last pull succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_sync_at: Option<DateTime<Utc>>,
    /// How many pulls failed in a row.
    #[serde(default)]
    pub(crate) failures: u32,
}

impl SyncState {
    /// The state a document holds; a document of another shape is the state of an account that was never pulled.
    pub(crate) fn read(document: &serde_json::Value) -> Self {
        serde_json::from_value(document.clone()).unwrap_or_default()
    }

    /// The document of the state.
    pub(crate) fn document(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }

    /// Whether a worker may take the account at `now`: its next pull is due and nobody holds it.
    pub(crate) fn is_due(&self, now: DateTime<Utc>) -> bool {
        self.next_sync_at.is_none_or(|at| at <= now) && self.lease_until.is_none_or(|until| until <= now)
    }

    /// When the account is due, for ordering: the one that waited longest is pulled first.
    pub(crate) fn due_at(&self) -> DateTime<Utc> {
        self.next_sync_at.unwrap_or(DateTime::<Utc>::MIN_UTC)
    }
}

/// `now` plus `delay`, saturating.
pub(crate) fn after(now: DateTime<Utc>, delay: Duration) -> DateTime<Utc> {
    TimeDelta::from_std(delay)
        .ok()
        .and_then(|delay| now.checked_add_signed(delay))
        .unwrap_or(DateTime::<Utc>::MAX_UTC)
}

/// The wait after `failures` pulls that failed in a row: a third of the interval, doubling with every failure, at most
/// `longest`.
pub(crate) fn backoff(interval: Duration, failures: u32, longest: Duration) -> Duration {
    let base = interval / 3;
    let doublings = failures.saturating_sub(1).min(16);
    base.saturating_mul(1_u32 << doublings).min(longest)
}

/// Why a pull failed. The code is what the `external_account.sync_failed` event and the metrics say; the message is what the
/// operator reads in `last_error` (it names no address and no provider text).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The provider says that the refresh token is no longer valid (`invalid_grant`: the person removed the access, or it
    /// expired or was revoked), or the account has no refresh token. Only a new connection helps. A provider that refuses the
    /// **client** of the deployment (an expired or rotated client secret) is not this: that is the operator's to fix, it fails
    /// every account alike and no account is switched off for it (it is [`Failure::Internal`]).
    AuthRevoked,
    /// The provider refuses a fresh token or the calendar: access was narrowed, or the calendar is gone.
    ProviderRejected,
    /// The provider cannot be reached, is throttling or answers something that is not its API.
    ProviderUnavailable,
    /// The calendar has more events in the pulled window than the adapter imports. A new token does not help, and the window
    /// is the operator's to narrow (`history_days`, `future_days`).
    TooLarge,
    /// The mirror calendar was deleted or cannot be written.
    MirrorMissing,
    /// The stored tokens cannot be opened, or something else that is ours.
    Internal,
}

impl Failure {
    /// The short reason for events and metrics.
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::AuthRevoked => "auth_revoked",
            Self::ProviderRejected => "provider_rejected",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::TooLarge => "too_large",
            Self::MirrorMissing => "mirror_missing",
            Self::Internal => "internal",
        }
    }

    /// What `last_error` says.
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::AuthRevoked => {
                "auth_revoked: the provider no longer accepts the stored access; connect the account again"
            }
            Self::ProviderRejected => {
                "provider_rejected: the provider refused the request; it is tried again, and the account may need to be \
                 connected again"
            }
            Self::ProviderUnavailable => "provider_unavailable: the provider could not be reached; it is tried again",
            Self::TooLarge => {
                "too_large: the calendar has more events in the pulled window than the server imports; it is tried again"
            }
            Self::MirrorMissing => "mirror_missing: the mirror calendar of the account does not exist any more",
            Self::Internal => "internal: the account cannot be synchronized; see the log of the server",
        }
    }

    /// The status the account gets: only a failure that no retry can fix switches it off.
    pub(crate) const fn status(self) -> ExternalAccountStatus {
        match self {
            Self::AuthRevoked => ExternalAccountStatus::Disabled,
            _ => ExternalAccountStatus::Error,
        }
    }

    /// The failure of a call to the provider.
    pub(crate) const fn of(error: &PortError) -> Self {
        match error.kind {
            PortErrorKind::Rejected => Self::ProviderRejected,
            PortErrorKind::Unavailable | PortErrorKind::Timeout => Self::ProviderUnavailable,
            PortErrorKind::Invalid | PortErrorKind::Unsupported | PortErrorKind::Internal => Self::Internal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + seconds, 0).unwrap()
    }

    #[test]
    fn a_state_that_was_never_written_is_due_and_unheld() {
        let state = SyncState::default();
        assert!(state.is_due(at(0)));
        assert_eq!(state.document(), serde_json::json!({"failures": 0}));
        assert_eq!(SyncState::read(&serde_json::json!({})), SyncState::default());
        assert_eq!(SyncState::read(&serde_json::Value::Null), SyncState::default());
        assert_eq!(
            SyncState::read(&serde_json::json!({"cursor": 7})),
            SyncState::default(),
            "a document of another shape is not read"
        );
    }

    #[test]
    fn an_account_is_due_when_its_time_has_come_and_nobody_holds_it() {
        let state = SyncState {
            next_sync_at: Some(at(60)),
            ..SyncState::default()
        };
        assert!(!state.is_due(at(59)));
        assert!(state.is_due(at(60)));
        let held = SyncState {
            lease_until: Some(at(120)),
            ..state
        };
        assert!(!held.is_due(at(100)), "another worker holds it");
        assert!(held.is_due(at(120)), "the claim ran out");
    }

    #[test]
    fn a_state_survives_its_document() {
        let state = SyncState {
            calendar: Some("primary".to_owned()),
            cursor: Some("t-1".to_owned()),
            next_sync_at: Some(at(900)),
            lease_until: None,
            last_sync_at: Some(at(0)),
            failures: 2,
        };
        assert_eq!(SyncState::read(&state.document()), state);
        assert!(
            state.document().get("lease_until").is_none(),
            "what is not set is not written"
        );
    }

    #[test]
    fn the_backoff_doubles_from_a_third_of_the_interval_up_to_the_longest_wait() {
        let interval = Duration::from_mins(15);
        let longest = Duration::from_hours(1);
        let waits: Vec<u64> = (0..7).map(|n| backoff(interval, n, longest).as_secs() / 60).collect();
        assert_eq!(
            waits,
            vec![5, 5, 10, 20, 40, 60, 60],
            "the first failure waits the base, no failure too"
        );
        assert_eq!(backoff(interval, u32::MAX, longest), longest, "no overflow");
        assert_eq!(after(at(0), Duration::from_secs(90)), at(90));
        assert_eq!(after(at(0), Duration::MAX), DateTime::<Utc>::MAX_UTC);
    }

    #[test]
    fn only_a_revoked_refresh_token_switches_an_account_off() {
        for failure in [
            Failure::ProviderRejected,
            Failure::ProviderUnavailable,
            Failure::TooLarge,
            Failure::MirrorMissing,
            Failure::Internal,
        ] {
            assert_eq!(failure.status(), ExternalAccountStatus::Error, "{failure:?}");
        }
        assert_eq!(Failure::AuthRevoked.status(), ExternalAccountStatus::Disabled);
    }

    #[test]
    fn provider_errors_become_failures_and_the_messages_name_no_one() {
        let of = |kind| Failure::of(&PortError::new(kind, "Google refused anna@example.org"));
        assert_eq!(of(PortErrorKind::Rejected), Failure::ProviderRejected);
        assert_eq!(of(PortErrorKind::Unavailable), Failure::ProviderUnavailable);
        assert_eq!(of(PortErrorKind::Timeout), Failure::ProviderUnavailable);
        for kind in [
            PortErrorKind::Invalid,
            PortErrorKind::Unsupported,
            PortErrorKind::Internal,
        ] {
            assert_eq!(of(kind), Failure::Internal);
        }
        for failure in [
            Failure::AuthRevoked,
            Failure::ProviderRejected,
            Failure::ProviderUnavailable,
            Failure::TooLarge,
            Failure::MirrorMissing,
            Failure::Internal,
        ] {
            assert!(failure.message().starts_with(failure.code()), "{failure:?}");
            assert!(!failure.message().contains('@'), "{failure:?}");
        }
    }
}
