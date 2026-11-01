//! Port errors: `StoreError`, `UniqueKey`, `PortError`, `HandlerError` and `PluginError`.
//!
//! Every adapter reports failures with one of these typed errors (`ENGINEERING_RULES` R5). The application layer
//! maps them exactly once (`From<StoreError>` and `From<PortError>` for its own error type), so a protocol crate
//! never sees adapter text. The messages carried here are for operators and logs only and never reach a client.
//!
//! * [`StoreError`] is the error of the [`Database`](crate::store::Database) port and its repositories.
//! * [`PortError`] is the error of every other outbound port (mail, templates, HTTP egress, crypto, providers).
//! * [`HandlerError`] is returned by outbox handlers and event sinks and tells the dispatcher whether to retry.
//! * [`PluginError`] is returned while the plugin registry is filled and while adapters are built at startup.

use core::fmt;

/// The unique constraint a [`StoreError::UniqueViolation`] refers to.
///
/// The application layer turns the key into the precondition the protocol expects (for example
/// [`UniqueKey::ObjectUid`] becomes `CALDAV:no-uid-conflict`). New constraints are added over time, so the enum is
/// `#[non_exhaustive]`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum UniqueKey {
    /// `tenants.slug`.
    TenantSlug,
    /// `tenants.login_domain` (case-insensitive).
    LoginDomain,
    /// `(tenant_id, principals.name)`.
    PrincipalName,
    /// `(tenant_id, principals.external_ref)`.
    ExternalRef,
    /// `(tenant_id, lower(principal_addresses.address))`; addresses of deleted principals stay reserved.
    Address,
    /// `(tenant_id, owner_id, calendars.slug)` among live calendars.
    CalendarSlug,
    /// `(tenant_id, principal_id, calendar_bindings.slug)`.
    BindingSlug,
    /// `(tenant_id, principal_id, calendar_bindings.calendar_id)`: the principal already has a binding.
    BindingCalendar,
    /// `(tenant_id, calendar_id, calendar_grants.grantee_id)`.
    Grant,
    /// `(tenant_id, calendar_id, calendar_objects.uri)`.
    ObjectUri,
    /// `(tenant_id, calendar_id, calendar_objects.uid)`.
    ObjectUid,
    /// Scheduling objects are unique per owner and UID (`C:unique-scheduling-object-resource`).
    SchedulingUid,
    /// `(tenant_id, calendar_id, calendar_objects.external_key)`.
    ExternalKey,
    /// `(tenant_id, principal_id, notifications.uri)`.
    NotificationUri,
    /// `(tenant_id, principal_id, scheduling_inbox.uri)`.
    InboxUri,
    /// The credential prefix of app passwords, API tokens, feed tokens and RSVP tokens.
    CredentialPrefix,
    /// `(tenant_id, token_id, idempotency_keys.key)`.
    IdempotencyKey,
    /// `oauth_states.state_hash`.
    OAuthState,
}

impl UniqueKey {
    /// Every key, for exhaustive mapping tests.
    pub const ALL: [Self; 18] = [
        Self::TenantSlug,
        Self::LoginDomain,
        Self::PrincipalName,
        Self::ExternalRef,
        Self::Address,
        Self::CalendarSlug,
        Self::BindingSlug,
        Self::BindingCalendar,
        Self::Grant,
        Self::ObjectUri,
        Self::ObjectUid,
        Self::SchedulingUid,
        Self::ExternalKey,
        Self::NotificationUri,
        Self::InboxUri,
        Self::CredentialPrefix,
        Self::IdempotencyKey,
        Self::OAuthState,
    ];

    /// A stable `snake_case` name for logs and metrics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TenantSlug => "tenant_slug",
            Self::LoginDomain => "login_domain",
            Self::PrincipalName => "principal_name",
            Self::ExternalRef => "external_ref",
            Self::Address => "address",
            Self::CalendarSlug => "calendar_slug",
            Self::BindingSlug => "binding_slug",
            Self::BindingCalendar => "binding_calendar",
            Self::Grant => "grant",
            Self::ObjectUri => "object_uri",
            Self::ObjectUid => "object_uid",
            Self::SchedulingUid => "scheduling_uid",
            Self::ExternalKey => "external_key",
            Self::NotificationUri => "notification_uri",
            Self::InboxUri => "inbox_uri",
            Self::CredentialPrefix => "credential_prefix",
            Self::IdempotencyKey => "idempotency_key",
            Self::OAuthState => "oauth_state",
        }
    }
}

impl fmt::Display for UniqueKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

/// The error of the `Database` port and its repositories.
///
/// Reads of resources that do not exist in the transaction's tenant, including resources of other tenants, always
/// answer [`StoreError::NotFound`]; there is no variant that distinguishes "exists elsewhere".
///
/// The enum is `#[non_exhaustive]`: adapters and the application may meet variants a later release adds, so a
/// `match` outside this crate needs a catch-all arm that treats the unknown error as [`StoreError::Internal`].
/// [`StoreError::PreconditionFailed`] means one thing only (a stale `version`, `If-Match` or `If-None-Match`);
/// the other reasons a conditional call can fail have their own variants ([`StoreError::InvalidSyncToken`],
/// [`StoreError::LeaseLost`]).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// The row does not exist or is invisible to the transaction's tenant.
    #[error("not found")]
    NotFound,
    /// A unique constraint was violated.
    #[error("unique constraint violated: {0}")]
    UniqueViolation(UniqueKey),
    /// A conditional write did not match the stored state (stale `version`, `If-Match` or `If-None-Match`).
    #[error("precondition failed")]
    PreconditionFailed,
    /// The database aborted the transaction because of a concurrent update; the caller retries it.
    #[error("serialization failure")]
    SerializationFailure,
    /// The database cannot be reached or the pool is exhausted.
    #[error("store unavailable")]
    Unavailable,
    /// The operation exceeded its time limit: a statement that ran too long, a transaction that sat idle, a pool
    /// that stayed exhausted, or a lock that could not be taken in time (a writer queued behind a busy calendar).
    /// Repeating the whole transaction may succeed ([`StoreError::is_retryable`]); a protocol layer that gives up
    /// answers 503 with `Retry-After`.
    #[error("store operation timed out")]
    Timeout,
    /// The sync token cannot be resumed: it is from another epoch, older than the pruned history, or from the
    /// future ([`ChangeRepo::since`](crate::store::ChangeRepo::since)). The application answers
    /// `DAV:valid-sync-token` (API: 410 `sync-token-expired`), never the 412 of a stale `If-Match`.
    #[error("sync token cannot be resumed")]
    InvalidSyncToken,
    /// The caller no longer holds the lease it tried to settle: the outbox record or idempotency key was settled,
    /// released or reclaimed by someone else after the caller's lease ran out. Nothing was changed; the caller
    /// drops its result (the other holder decides the outcome).
    #[error("lease lost")]
    LeaseLost,
    /// The store does not implement the operation (an additive port method the adapter has not overridden).
    #[error("operation not supported by this store")]
    Unsupported,
    /// A value cannot be stored: text containing U+0000, which neither PostgreSQL `text` nor `jsonb` accepts.
    /// Both adapters refuse it the same way, so tests on the in-memory adapter see what production answers. The
    /// text is for operators; it names the kind of field, never the value.
    #[error("value cannot be stored: {0}")]
    InvalidData(String),
    /// An unexpected failure (driver error, corrupt row, bug). The text is for operators only.
    #[error("internal store error: {0}")]
    Internal(String),
}

impl StoreError {
    /// An [`StoreError::Internal`] with the given operator-facing text.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }

    /// Whether repeating the transaction may succeed.
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::SerializationFailure | Self::Unavailable | Self::Timeout)
    }

    /// A stable `snake_case` name for logs and metric labels.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::UniqueViolation(_) => "unique_violation",
            Self::PreconditionFailed => "precondition_failed",
            Self::SerializationFailure => "serialization_failure",
            Self::Unavailable => "unavailable",
            Self::Timeout => "timeout",
            Self::InvalidSyncToken => "invalid_sync_token",
            Self::LeaseLost => "lease_lost",
            Self::Unsupported => "unsupported",
            Self::InvalidData(_) => "invalid_data",
            Self::Internal(_) => "internal",
        }
    }
}

/// The class of a [`PortError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PortErrorKind {
    /// The remote system cannot be reached; retrying later may succeed.
    Unavailable,
    /// The call exceeded its time limit; retrying later may succeed.
    Timeout,
    /// The remote system or a local policy refused the request (SMTP 5xx, egress policy, failed authentication of
    /// sealed data); retrying the same request will not help.
    Rejected,
    /// The request itself is malformed (unknown template, bad model, invalid token); retrying will not help.
    Invalid,
    /// The adapter does not support the operation (a capability the adapter documents it lacks, or an operation that
    /// is not implemented yet).
    Unsupported,
    /// An unexpected failure inside the adapter.
    Internal,
}

impl PortErrorKind {
    /// Every kind, in declaration order.
    pub const ALL: [Self; 6] = [
        Self::Unavailable,
        Self::Timeout,
        Self::Rejected,
        Self::Invalid,
        Self::Unsupported,
        Self::Internal,
    ];

    /// A stable `snake_case` name for logs and metric labels.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Timeout => "timeout",
            Self::Rejected => "rejected",
            Self::Invalid => "invalid",
            Self::Unsupported => "unsupported",
            Self::Internal => "internal",
        }
    }

    /// Whether repeating the call later may succeed.
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Unavailable | Self::Timeout)
    }
}

impl fmt::Display for PortErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

/// The error of every outbound port except the database.
///
/// The `message` is written for operators. It must not contain secrets, request bodies or e-mail addresses
/// (`ENGINEERING_RULES` R8) and never reaches a client.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{kind}: {message}")]
pub struct PortError {
    /// What went wrong, as far as callers need to react differently.
    pub kind: PortErrorKind,
    /// The operator-facing description.
    pub message: String,
}

impl PortError {
    /// Creates an error of any kind.
    pub fn new(kind: PortErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// The remote system cannot be reached.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(PortErrorKind::Unavailable, message)
    }

    /// The call timed out.
    pub fn timeout(message: impl Into<String>) -> Self {
        Self::new(PortErrorKind::Timeout, message)
    }

    /// The request was refused.
    pub fn rejected(message: impl Into<String>) -> Self {
        Self::new(PortErrorKind::Rejected, message)
    }

    /// The request is malformed.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(PortErrorKind::Invalid, message)
    }

    /// An unexpected adapter failure.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(PortErrorKind::Internal, message)
    }

    /// The stub for a port method that is not implemented yet.
    ///
    /// This is the only allowed stub (`ENGINEERING_RULES` R5): CI lists every remaining call, warns on pull
    /// requests and fails release tags. An adapter that permanently lacks a capability reports
    /// [`PortErrorKind::Unsupported`] through [`PortError::new`] instead.
    pub fn unsupported() -> Self {
        Self::new(PortErrorKind::Unsupported, "not implemented")
    }

    /// Whether repeating the call later may succeed.
    pub const fn is_retryable(&self) -> bool {
        self.kind.is_retryable()
    }
}

impl From<StoreError> for PortError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Unavailable => Self::unavailable("store unavailable"),
            StoreError::Timeout => Self::timeout("store operation timed out"),
            StoreError::NotFound => Self::invalid("not found"),
            StoreError::UniqueViolation(key) => Self::invalid(format!("unique constraint violated: {key}")),
            StoreError::PreconditionFailed => Self::invalid("precondition failed"),
            StoreError::SerializationFailure => Self::unavailable("serialization failure"),
            StoreError::InvalidSyncToken => Self::invalid("sync token cannot be resumed"),
            StoreError::LeaseLost => Self::rejected("lease lost"),
            StoreError::Unsupported => Self::new(PortErrorKind::Unsupported, "operation not supported by this store"),
            StoreError::InvalidData(message) => Self::invalid(format!("value cannot be stored: {message}")),
            StoreError::Internal(message) => Self::internal(message),
        }
    }
}

/// The error of outbox handlers and event sinks. The dispatcher retries [`HandlerError::Retryable`] failures with
/// backoff, dead-letters [`HandlerError::Permanent`] ones immediately and puts [`HandlerError::Defer`]red messages
/// back without counting an attempt.
///
/// The text of an error ends up in `outbox.last_error`, which every token with `outbox:manage` can read, so it is
/// written for the operators of the tenant: no secret, no address, no driver text and no relay output. The
/// conversions from [`StoreError`] and [`PortError`] therefore keep a fixed phrase for the class of the failure;
/// the detail goes to the operator log.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HandlerError {
    /// A transient failure; the message is delivered again later.
    #[error("retryable handler failure: {0}")]
    Retryable(String),
    /// A failure that repetition cannot fix (rejected recipient, malformed payload); the message goes dead.
    #[error("permanent handler failure: {0}")]
    Permanent(String),
    /// The handler did not try: a safety rail holds the message back (the mail rate limit, an open circuit
    /// breaker). The message is due again after `after`, and the claim does not count as an attempt, so a long
    /// hold never uses up `outbox.max_attempts`.
    #[error("deferred for {after:?}: {reason}")]
    Defer {
        /// How long to wait before the message is due again.
        after: std::time::Duration,
        /// Why the message waits (a static phrase for operators).
        reason: &'static str,
    },
}

impl HandlerError {
    /// A transient failure.
    pub fn retryable(message: impl Into<String>) -> Self {
        Self::Retryable(message.into())
    }

    /// A permanent failure.
    pub fn permanent(message: impl Into<String>) -> Self {
        Self::Permanent(message.into())
    }

    /// A hold: nothing was attempted; try again after `after` without counting an attempt.
    pub const fn defer(after: std::time::Duration, reason: &'static str) -> Self {
        Self::Defer { after, reason }
    }

    /// Whether the dispatcher should deliver the message again (a deferral included).
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Retryable(_) | Self::Defer { .. })
    }

    /// Whether the message was held back without an attempt.
    pub const fn is_deferred(&self) -> bool {
        matches!(self, Self::Defer { .. })
    }

    /// The operator-facing text.
    pub fn message(&self) -> &str {
        match self {
            Self::Retryable(message) | Self::Permanent(message) => message,
            Self::Defer { reason, .. } => reason,
        }
    }
}

impl From<PortError> for HandlerError {
    /// `Unavailable`, `Timeout` and `Internal` failures are retried (the dispatcher bounds the attempts); every
    /// other kind is permanent. The text names the class of the failure and nothing else: the adapter's message
    /// goes to the operator log.
    fn from(error: PortError) -> Self {
        tracing::warn!(kind = error.kind.as_str(), detail = %error.message, "a port failed in an outbox handler");
        let text = match error.kind {
            PortErrorKind::Unavailable => "an outbound service is not available",
            PortErrorKind::Timeout => "an outbound service did not answer in time",
            PortErrorKind::Rejected => "an outbound service refused the request",
            PortErrorKind::Invalid => "an outbound service cannot process the request",
            PortErrorKind::Unsupported => "an outbound service does not support the request",
            PortErrorKind::Internal => "an outbound service failed",
        };
        match error.kind {
            PortErrorKind::Unavailable | PortErrorKind::Timeout | PortErrorKind::Internal => {
                Self::Retryable(text.to_owned())
            }
            PortErrorKind::Rejected | PortErrorKind::Invalid | PortErrorKind::Unsupported => {
                Self::Permanent(text.to_owned())
            }
        }
    }
}

impl From<StoreError> for HandlerError {
    /// Contention, unavailability, timeouts and internal failures are retried; a missing row, a unique violation
    /// and a failed precondition are permanent. The text is a fixed phrase for the class of the failure: driver
    /// text (`StoreError::Internal`) goes to the operator log and never into the outbox.
    fn from(error: StoreError) -> Self {
        if let StoreError::Internal(detail) = &error {
            tracing::warn!(%detail, "the store failed in an outbox handler");
        }
        let text = match &error {
            StoreError::NotFound => "a record was not found",
            StoreError::UniqueViolation(_) => "the store refused a duplicate",
            StoreError::PreconditionFailed => "the store refused a stale write",
            StoreError::SerializationFailure => "the store reported a conflicting write",
            StoreError::Unavailable => "the store is not available",
            StoreError::Timeout => "the store did not answer in time",
            StoreError::InvalidSyncToken => "the store refused a sync token",
            StoreError::LeaseLost => "the lease of the record was lost",
            StoreError::Unsupported => "the store does not support the request",
            StoreError::InvalidData(_) => "the store refused a value",
            StoreError::Internal(_) => "the store failed",
        };
        if error.is_retryable() || matches!(error, StoreError::Internal(_)) {
            Self::Retryable(text.to_owned())
        } else {
            Self::Permanent(text.to_owned())
        }
    }
}

/// The error of the plugin registry and of adapter construction at startup.
///
/// These errors surface when the process starts (configuration and wiring), so their text is written for the
/// operator who edits the configuration.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PluginError {
    /// A plugin with this name is already registered for the port kind.
    #[error("plugin `{name}` is already registered for `{kind}`")]
    DuplicateName {
        /// The port kind.
        kind: &'static str,
        /// The plugin name.
        name: String,
    },
    /// A plugin name is empty, too long or contains characters other than `a-z`, `0-9`, `-` and `_`.
    #[error("invalid plugin name `{name}`: use 1 to 64 lowercase letters, digits, `-` or `_`, starting with a letter")]
    InvalidName {
        /// The rejected name.
        name: String,
    },
    /// A plugin names a dedicated table that no plugin can have: it is malformed, or it is `plugin` or `plugins`.
    #[error("invalid dedicated table `[{table}]`: {reason}")]
    InvalidTable {
        /// The rejected table.
        table: String,
        /// What a table must be.
        reason: &'static str,
    },
    /// Two plugins name the same dedicated table: a table has one owner.
    #[error("the dedicated table `[{table}]` already belongs to the {kind} plugin `{name}`; a table has one owner")]
    DuplicateTable {
        /// The table.
        table: String,
        /// The kind of the plugin that owns it.
        kind: &'static str,
        /// The name of the plugin that owns it.
        name: String,
    },
    /// The selected plugin does not exist.
    #[error("unknown {kind} plugin `{name}` (available: {})", .available.join(", "))]
    Unknown {
        /// The port kind.
        kind: &'static str,
        /// The selected name.
        name: String,
        /// The registered names, sorted.
        available: Vec<&'static str>,
    },
    /// A kind was built with the wrong cardinality (`build_single` for a chain, and so on).
    #[error("`{kind}` is a {expected} kind and cannot be built that way")]
    WrongCardinality {
        /// The port kind.
        kind: &'static str,
        /// What the kind is: `single`, `chain` or `set`.
        expected: &'static str,
    },
    /// A chain must name at least one plugin.
    #[error("`{kind}` needs at least one plugin")]
    EmptySelection {
        /// The port kind.
        kind: &'static str,
    },
    /// The same plugin is selected twice for a chain or set.
    #[error("plugin `{name}` is selected more than once for `{kind}`")]
    DuplicateSelection {
        /// The port kind.
        kind: &'static str,
        /// The repeated name.
        name: String,
    },
    /// The registered descriptor was registered for a different port type than the kind promises.
    #[error("plugin `{name}` for `{kind}` was registered with a different port type")]
    TypeMismatch {
        /// The port kind.
        kind: &'static str,
        /// The plugin name.
        name: String,
    },
    /// A plugin needs a lower tier that is not built yet (for example the database).
    #[error("plugin `{plugin}` needs the {dependency}, which is not available at this point of startup")]
    MissingDependency {
        /// The plugin that asked.
        plugin: String,
        /// The missing dependency, for example `database`.
        dependency: &'static str,
    },
    /// The plugin's configuration is invalid.
    #[error("invalid configuration for plugin `{plugin}`: {message}")]
    InvalidConfig {
        /// The plugin name.
        plugin: String,
        /// What is wrong, naming the key.
        message: String,
    },
    /// The plugin is not allowed in `production` mode (memory adapters).
    #[error("plugin `{plugin}` is not allowed when server.mode is \"production\"")]
    RefusedInProduction {
        /// The plugin name.
        plugin: String,
    },
    /// The adapter failed to start (for example the database is unreachable).
    #[error("plugin `{plugin}` failed to start: {source}")]
    Build {
        /// The plugin name.
        plugin: String,
        /// The adapter's failure.
        source: PortError,
    },
}

impl PluginError {
    /// The configuration of `plugin` is invalid.
    pub fn invalid_config(plugin: impl Into<String>, message: impl Into<String>) -> Self {
        Self::InvalidConfig {
            plugin: plugin.into(),
            message: message.into(),
        }
    }

    /// The adapter `plugin` failed to start with `source`.
    pub fn build(plugin: impl Into<String>, source: impl Into<PortError>) -> Self {
        Self::Build {
            plugin: plugin.into(),
            source: source.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_errors_classify_retryability_and_names() {
        let cases = [
            (StoreError::NotFound, false, "not_found"),
            (
                StoreError::UniqueViolation(UniqueKey::ObjectUid),
                false,
                "unique_violation",
            ),
            (StoreError::PreconditionFailed, false, "precondition_failed"),
            (StoreError::SerializationFailure, true, "serialization_failure"),
            (StoreError::Unavailable, true, "unavailable"),
            (StoreError::Timeout, true, "timeout"),
            (StoreError::InvalidSyncToken, false, "invalid_sync_token"),
            (StoreError::LeaseLost, false, "lease_lost"),
            (StoreError::Unsupported, false, "unsupported"),
            (StoreError::InvalidData("text".to_owned()), false, "invalid_data"),
            (StoreError::internal("boom"), false, "internal"),
        ];
        for (error, retryable, name) in cases {
            assert_eq!(error.is_retryable(), retryable, "{error}");
            assert_eq!(error.as_str(), name);
        }
    }

    #[test]
    fn unique_keys_have_unique_names() {
        let mut names: Vec<&str> = UniqueKey::ALL.iter().map(|key| key.as_str()).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total);
        assert_eq!(UniqueKey::ObjectUid.to_string(), "object_uid");
        assert_eq!(
            StoreError::UniqueViolation(UniqueKey::CalendarSlug).to_string(),
            "unique constraint violated: calendar_slug"
        );
    }

    #[test]
    fn port_errors_carry_kind_and_message() {
        let error = PortError::rejected("relay refused the recipient");
        assert_eq!(error.kind, PortErrorKind::Rejected);
        assert_eq!(error.to_string(), "rejected: relay refused the recipient");
        assert!(!error.is_retryable());
        assert!(PortError::timeout("slow").is_retryable());
        assert!(PortError::unavailable("down").is_retryable());
        for kind in PortErrorKind::ALL {
            assert_eq!(PortError::new(kind, "x").kind, kind);
            assert_eq!(kind.to_string(), kind.as_str());
        }
        let stub: fn() -> PortError = PortError::unsupported;
        assert_eq!(stub().kind, PortErrorKind::Unsupported);
    }

    #[test]
    fn store_errors_convert_to_port_errors() {
        assert_eq!(
            PortError::from(StoreError::Unavailable).kind,
            PortErrorKind::Unavailable
        );
        assert_eq!(PortError::from(StoreError::Timeout).kind, PortErrorKind::Timeout);
        assert_eq!(
            PortError::from(StoreError::SerializationFailure).kind,
            PortErrorKind::Unavailable
        );
        assert_eq!(PortError::from(StoreError::NotFound).kind, PortErrorKind::Invalid);
        assert_eq!(
            PortError::from(StoreError::InvalidSyncToken).kind,
            PortErrorKind::Invalid
        );
        assert_eq!(PortError::from(StoreError::LeaseLost).kind, PortErrorKind::Rejected);
        assert_eq!(
            PortError::from(StoreError::Unsupported).kind,
            PortErrorKind::Unsupported
        );
        assert_eq!(
            PortError::from(StoreError::InvalidData("text".to_owned())).kind,
            PortErrorKind::Invalid
        );
        assert_eq!(
            PortError::from(StoreError::internal("driver")).to_string(),
            "internal: driver"
        );
    }

    #[test]
    fn handler_errors_decide_retries() {
        assert!(HandlerError::retryable("later").is_retryable());
        assert!(!HandlerError::permanent("never").is_retryable());
        assert_eq!(HandlerError::permanent("never").message(), "never");
        let held = HandlerError::defer(std::time::Duration::from_secs(5), "the rate limit is reached");
        assert!(held.is_retryable() && held.is_deferred());
        assert_eq!(held.message(), "the rate limit is reached");
        assert!(!HandlerError::retryable("later").is_deferred());
        for (kind, retryable) in [
            (PortErrorKind::Unavailable, true),
            (PortErrorKind::Timeout, true),
            (PortErrorKind::Internal, true),
            (PortErrorKind::Rejected, false),
            (PortErrorKind::Invalid, false),
            (PortErrorKind::Unsupported, false),
        ] {
            assert_eq!(
                HandlerError::from(PortError::new(kind, "x")).is_retryable(),
                retryable,
                "{kind}"
            );
        }
        for (error, retryable) in [
            (StoreError::SerializationFailure, true),
            (StoreError::Unavailable, true),
            (StoreError::Timeout, true),
            (StoreError::internal("x"), true),
            (StoreError::NotFound, false),
            (StoreError::PreconditionFailed, false),
            (StoreError::InvalidSyncToken, false),
            (StoreError::LeaseLost, false),
            (StoreError::Unsupported, false),
            (StoreError::UniqueViolation(UniqueKey::Grant), false),
        ] {
            assert_eq!(HandlerError::from(error.clone()).is_retryable(), retryable, "{error}");
        }
    }

    #[test]
    fn conversions_keep_the_class_and_drop_the_detail() {
        let driver = StoreError::internal("password=hunter2 host=db.internal");
        assert_eq!(HandlerError::from(driver).message(), "the store failed");
        let relay = PortError::unavailable("relay mail.internal answered 451 for ann@example.org");
        assert_eq!(
            HandlerError::from(relay).message(),
            "an outbound service is not available"
        );
        for kind in PortErrorKind::ALL {
            let converted = HandlerError::from(PortError::new(kind, "detail with secret"));
            assert!(!converted.message().contains("secret"), "{kind}: {converted}");
        }
        for error in [
            StoreError::NotFound,
            StoreError::UniqueViolation(UniqueKey::Grant),
            StoreError::PreconditionFailed,
            StoreError::SerializationFailure,
            StoreError::Unavailable,
            StoreError::Timeout,
        ] {
            let converted = HandlerError::from(error.clone());
            assert!(
                !converted.message().is_empty() && !converted.message().contains("grant"),
                "{error}: {converted}"
            );
        }
    }

    #[test]
    fn plugin_errors_read_like_configuration_advice() {
        let error = PluginError::Unknown {
            kind: "mail_transport",
            name: "smtpp".to_owned(),
            available: vec!["memory", "smtp"],
        };
        assert_eq!(
            error.to_string(),
            "unknown mail_transport plugin `smtpp` (available: memory, smtp)"
        );
        let error = PluginError::build("smtp", PortError::unavailable("connection refused"));
        assert_eq!(
            error.to_string(),
            "plugin `smtp` failed to start: unavailable: connection refused"
        );
        assert_eq!(
            PluginError::invalid_config("smtp", "port must be 1..=65535").to_string(),
            "invalid configuration for plugin `smtp`: port must be 1..=65535"
        );
    }
}
