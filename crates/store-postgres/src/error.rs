//! Mapping of database errors to `StoreError`.
//!
//! The mapping is the only place that looks at SQLSTATE codes and constraint names. Unique violations become
//! [`StoreError::UniqueViolation`] with the [`UniqueKey`] of the constraint (the names are fixed by the initial
//! migration), foreign key violations become [`StoreError::NotFound`] (a parent row that does not exist in the
//! tenant cannot be referenced, and a row of another tenant is indistinguishable from a missing one), conflicts
//! the database resolves by aborting become [`StoreError::SerializationFailure`], and connection trouble becomes
//! [`StoreError::Unavailable`] or [`StoreError::Timeout`] (a statement or a lock wait that exceeded its limit,
//! `lock_not_available` included: the application may retry it like a serialization failure), and text PostgreSQL
//! cannot store (U+0000) becomes [`StoreError::InvalidData`]. Everything else is [`StoreError::Internal`] with a
//! text for operators that never contains row data.

use davhaven_ports::{StoreError, UniqueKey};

/// The unique constraints and unique indexes of the schema and the key each one reports.
///
/// A test asserts that every [`UniqueKey`] has an entry, so a new key cannot be forgotten.
pub const UNIQUE_CONSTRAINTS: &[(&str, UniqueKey)] = &[
    ("tenants_slug_key", UniqueKey::TenantSlug),
    ("tenants_login_domain_key", UniqueKey::LoginDomain),
    ("principals_name_key", UniqueKey::PrincipalName),
    ("principals_external_ref_key", UniqueKey::ExternalRef),
    ("principal_addresses_address_key", UniqueKey::Address),
    ("calendars_slug_key", UniqueKey::CalendarSlug),
    ("calendar_bindings_slug_key", UniqueKey::BindingSlug),
    ("calendar_bindings_calendar_key", UniqueKey::BindingCalendar),
    ("calendar_grants_grantee_key", UniqueKey::Grant),
    ("calendar_objects_uri_key", UniqueKey::ObjectUri),
    ("calendar_objects_uid_key", UniqueKey::ObjectUid),
    ("calendar_objects_scheduling_uid_key", UniqueKey::SchedulingUid),
    ("calendar_objects_external_key_key", UniqueKey::ExternalKey),
    ("notifications_uri_key", UniqueKey::NotificationUri),
    ("scheduling_inbox_uri_key", UniqueKey::InboxUri),
    ("app_passwords_prefix_key", UniqueKey::CredentialPrefix),
    ("api_tokens_prefix_key", UniqueKey::CredentialPrefix),
    ("feed_tokens_prefix_key", UniqueKey::CredentialPrefix),
    ("rsvp_tokens_prefix_key", UniqueKey::CredentialPrefix),
    ("idempotency_keys_key", UniqueKey::IdempotencyKey),
    ("oauth_states_hash_key", UniqueKey::OAuthState),
];

/// The key of the unique constraint or index with this name.
pub fn unique_key(constraint: &str) -> Option<UniqueKey> {
    UNIQUE_CONSTRAINTS
        .iter()
        .find(|(name, _)| *name == constraint)
        .map(|(_, key)| *key)
}

/// The SQLSTATE classes and codes the mapping distinguishes.
mod code {
    /// `unique_violation`.
    pub(super) const UNIQUE_VIOLATION: &str = "23505";
    /// `foreign_key_violation`.
    pub(super) const FOREIGN_KEY_VIOLATION: &str = "23503";
    /// `serialization_failure`.
    pub(super) const SERIALIZATION_FAILURE: &str = "40001";
    /// `deadlock_detected`.
    pub(super) const DEADLOCK: &str = "40P01";
    /// `query_canceled` (statement timeout).
    pub(super) const QUERY_CANCELED: &str = "57014";
    /// `lock_not_available` (lock timeout).
    pub(super) const LOCK_NOT_AVAILABLE: &str = "55P03";
    /// `read_only_sql_transaction`.
    pub(super) const READ_ONLY: &str = "25006";
    /// `idle_in_transaction_session_timeout`.
    pub(super) const IDLE_IN_TRANSACTION_TIMEOUT: &str = "25P03";
    /// `admin_shutdown`.
    pub(super) const ADMIN_SHUTDOWN: &str = "57P01";
    /// `crash_shutdown`.
    pub(super) const CRASH_SHUTDOWN: &str = "57P02";
    /// `cannot_connect_now`.
    pub(super) const CANNOT_CONNECT_NOW: &str = "57P03";
    /// `too_many_connections`.
    pub(super) const TOO_MANY_CONNECTIONS: &str = "53300";
    /// `insufficient_privilege`, which also reports a violated row-level security policy.
    pub(super) const INSUFFICIENT_PRIVILEGE: &str = "42501";
    /// `character_not_in_repertoire`: text that contains U+0000 (or another byte sequence the encoding rejects).
    pub(super) const CHARACTER_NOT_IN_REPERTOIRE: &str = "22021";
    /// `untranslatable_character`: a `jsonb` value with the escape `\u0000`, which cannot be stored as text.
    pub(super) const UNTRANSLATABLE_CHARACTER: &str = "22P05";
    /// The class of connection exceptions.
    pub(super) const CONNECTION_CLASS: &str = "08";
}

/// Maps a driver error to the error of the `Database` port.
pub fn map_sqlx(error: sqlx::Error) -> StoreError {
    match error {
        sqlx::Error::Database(database) => {
            let code = database.code().map(std::borrow::Cow::into_owned).unwrap_or_default();
            let constraint = database.constraint().map(str::to_owned);
            match code.as_str() {
                code::UNIQUE_VIOLATION => match constraint.as_deref().and_then(unique_key) {
                    Some(key) => StoreError::UniqueViolation(key),
                    None => StoreError::internal(format!(
                        "unique violation on constraint `{}` that has no key",
                        constraint.as_deref().unwrap_or("?")
                    )),
                },
                code::FOREIGN_KEY_VIOLATION => StoreError::NotFound,
                code::SERIALIZATION_FAILURE | code::DEADLOCK => StoreError::SerializationFailure,
                code::QUERY_CANCELED | code::LOCK_NOT_AVAILABLE | code::IDLE_IN_TRANSACTION_TIMEOUT => {
                    StoreError::Timeout
                }
                code::ADMIN_SHUTDOWN | code::CRASH_SHUTDOWN | code::CANNOT_CONNECT_NOW | code::TOO_MANY_CONNECTIONS => {
                    StoreError::Unavailable
                }
                code::CHARACTER_NOT_IN_REPERTOIRE | code::UNTRANSLATABLE_CHARACTER => {
                    StoreError::InvalidData("text that contains the character U+0000".to_owned())
                }
                code::READ_ONLY => StoreError::internal("write attempted in a read-only transaction"),
                code::INSUFFICIENT_PRIVILEGE => StoreError::internal(format!(
                    "the database refused the statement for lack of privilege or by a row-level security policy ({})",
                    constraint.as_deref().unwrap_or("no constraint")
                )),
                other if other.starts_with(code::CONNECTION_CLASS) => StoreError::Unavailable,
                other => StoreError::internal(format!("database error {other}: {}", database.message())),
            }
        }
        sqlx::Error::PoolTimedOut => StoreError::Timeout,
        sqlx::Error::PoolClosed
        | sqlx::Error::Io(_)
        | sqlx::Error::Tls(_)
        | sqlx::Error::WorkerCrashed
        | sqlx::Error::BeginFailed => StoreError::Unavailable,
        other => StoreError::internal(format!("database driver error: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn every_unique_key_has_a_constraint() {
        let mapped: BTreeSet<UniqueKey> = UNIQUE_CONSTRAINTS.iter().map(|(_, key)| *key).collect();
        for key in UniqueKey::ALL {
            assert!(mapped.contains(&key), "{key} has no constraint in UNIQUE_CONSTRAINTS");
        }
    }

    #[test]
    fn constraint_names_are_unique() {
        let names: BTreeSet<&str> = UNIQUE_CONSTRAINTS.iter().map(|(name, _)| *name).collect();
        assert_eq!(names.len(), UNIQUE_CONSTRAINTS.len());
    }

    #[test]
    fn unique_keys_are_found_by_constraint_name() {
        assert_eq!(unique_key("calendars_slug_key"), Some(UniqueKey::CalendarSlug));
        assert_eq!(unique_key("rsvp_tokens_prefix_key"), Some(UniqueKey::CredentialPrefix));
        assert_eq!(unique_key("principals_pkey"), None);
    }

    #[test]
    fn driver_errors_without_a_database_cause_are_classified() {
        assert_eq!(map_sqlx(sqlx::Error::PoolTimedOut), StoreError::Timeout);
        assert_eq!(map_sqlx(sqlx::Error::PoolClosed), StoreError::Unavailable);
        assert_eq!(map_sqlx(sqlx::Error::WorkerCrashed), StoreError::Unavailable);
        assert_eq!(
            map_sqlx(sqlx::Error::Io(std::io::Error::other("reset"))),
            StoreError::Unavailable
        );
        assert!(matches!(map_sqlx(sqlx::Error::RowNotFound), StoreError::Internal(_)));
        assert!(matches!(
            map_sqlx(sqlx::Error::Protocol("bad".to_owned())),
            StoreError::Internal(_)
        ));
    }
}
