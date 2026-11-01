//! Configuration owned by the application layer.
//!
//! Each section is the typed form of one table of the configuration file (PLAN F0.9): `[mail]`, `[scheduling]`,
//! `[sharing]`, `[retention]`, `[outbox]` and `[feeds]`. Every struct rejects unknown keys, has a default for
//! every key (the defaults of the plan) and is validated at startup with an actionable error. `davhaven-server`
//! composes the sections into its `Config` and hands the validated values to the application as [`AppConfig`].
//!
//! Per-tenant variation (sender, locale, external policy, sharing behavior) is tenant data (`TenantSettings`), not
//! configuration; these sections hold the server-wide ceilings and defaults.

use core::fmt;
use std::time::Duration;

use davhaven_domain::{DomainName, Email, EventDuration};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::sync_engine::{PASS_BUDGET, STALL_LIMIT, STALL_MARGIN};

/// Why a configuration section is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigError {
    section: &'static str,
    key: &'static str,
    reason: &'static str,
}

impl ConfigError {
    /// An error for `key` of the table `section`; the protocol crates use it for the tables they own.
    pub const fn new(section: &'static str, key: &'static str, reason: &'static str) -> Self {
        Self { section, key, reason }
    }

    /// The table of the configuration file, for example `outbox`.
    pub const fn section(&self) -> &'static str {
        self.section
    }

    /// The key inside the table.
    pub const fn key(&self) -> &'static str {
        self.key
    }

    /// The rule that was violated.
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid configuration `{}.{}`: {}",
            self.section, self.key, self.reason
        )
    }
}

impl std::error::Error for ConfigError {}

fn positive(section: &'static str, key: &'static str, value: u64) -> Result<(), ConfigError> {
    if value == 0 {
        Err(ConfigError::new(section, key, "must be greater than zero"))
    } else {
        Ok(())
    }
}

/// Whether outgoing iMIP mail is sent from the tenant's service address or from the organizer's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MailFromMode {
    /// `From` and `Sender` are the tenant's service address (`"{organizer} via {tenant}" <noreply@domain>`) and
    /// `Reply-To` is the organizer. The default; it passes SPF, DKIM and DMARC for the sender domain.
    #[default]
    Service,
    /// `From` is the organizer's address. Only allowed for organizers in verified domains of the tenant.
    Organizer,
}

/// The `[mail]` table: policy for outgoing mail, independent of the transport.
///
/// The staging safety options (`redirect_all_to`, `allowed_recipient_domains`) keep test deployments from mailing
/// real people.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct MailConfig {
    /// How the `From` header is formed.
    pub from_mode: MailFromMode,
    /// The most mails the server sends per minute (all tenants together).
    pub rate_limit_per_minute: u32,
    /// After this many failed sends in a row the circuit breaker opens and mail waits in the outbox.
    pub max_consecutive_failures: u32,
    /// When not empty, only recipients in these domains receive mail; others are dropped and recorded.
    pub allowed_recipient_domains: Vec<DomainName>,
    /// When set, every mail goes to this address instead of its recipients (staging).
    pub redirect_all_to: Option<Email>,
}

impl Default for MailConfig {
    fn default() -> Self {
        Self {
            from_mode: MailFromMode::Service,
            rate_limit_per_minute: 120,
            max_consecutive_failures: 5,
            allowed_recipient_domains: Vec::new(),
            redirect_all_to: None,
        }
    }
}

impl MailConfig {
    /// Checks that every value is usable.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] naming the first unusable key.
    pub fn validate(&self) -> Result<(), ConfigError> {
        positive("mail", "rate_limit_per_minute", self.rate_limit_per_minute.into())?;
        positive("mail", "max_consecutive_failures", self.max_consecutive_failures.into())
    }
}

/// The `[scheduling.inbound_itip]` table: the endpoint for mail gateways (PLAN 2.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct InboundItipConfig {
    /// Whether the inbound endpoint accepts messages at all. Off by default.
    pub enabled: bool,
    /// Whether the gateway must report a passing DMARC verdict; anything else is quarantined.
    pub require_dmarc_pass: bool,
}

impl Default for InboundItipConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            require_dmarc_pass: true,
        }
    }
}

/// The `[scheduling]` table: ceilings for server-side scheduling (PLAN 2.8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct SchedulingConfig {
    /// Internal attendees up to this number receive the invitation in the organizer's transaction; above it
    /// delivery is queued (`internal_delivery`).
    pub max_sync_internal_attendees: u32,
    /// The most external recipients of one event.
    pub external_per_event: u32,
    /// The most external recipients one organizer may invite per hour.
    pub external_per_organizer_per_hour: u32,
    /// The most external recipients one tenant may invite per day.
    pub external_per_tenant_per_day: u32,
    /// The inbound iTIP endpoint.
    pub inbound_itip: InboundItipConfig,
}

impl Default for SchedulingConfig {
    fn default() -> Self {
        Self {
            max_sync_internal_attendees: 50,
            external_per_event: 50,
            external_per_organizer_per_hour: 100,
            external_per_tenant_per_day: 1000,
            inbound_itip: InboundItipConfig::default(),
        }
    }
}

impl SchedulingConfig {
    /// Checks that every value is usable.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] naming the first unusable key.
    pub fn validate(&self) -> Result<(), ConfigError> {
        positive(
            "scheduling",
            "max_sync_internal_attendees",
            self.max_sync_internal_attendees.into(),
        )?;
        positive("scheduling", "external_per_event", self.external_per_event.into())?;
        positive(
            "scheduling",
            "external_per_organizer_per_hour",
            self.external_per_organizer_per_hour.into(),
        )?;
        positive(
            "scheduling",
            "external_per_tenant_per_day",
            self.external_per_tenant_per_day.into(),
        )?;
        if self.external_per_event > self.external_per_organizer_per_hour {
            return Err(ConfigError::new(
                "scheduling",
                "external_per_event",
                "must not exceed external_per_organizer_per_hour",
            ));
        }
        Ok(())
    }
}

/// The `[sharing]` table: the server-wide switch for CalendarServer sharing. Tenants refine it with
/// `TenantSettings::sharing`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct SharingConfig {
    /// Whether calendar sharing from client apps is available at all.
    pub enabled: bool,
}

impl Default for SharingConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// The `[retention]` table: how long the cleanup worker keeps data (PLAN 2.18).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct RetentionConfig {
    /// Days to keep processed outbox messages.
    pub outbox_done_days: u32,
    /// Days to keep dead outbox messages for inspection.
    pub outbox_dead_days: u32,
    /// Days to keep the change log of calendars (older tokens answer `valid-sync-token`).
    pub collection_changes_days: u32,
    /// Days to keep audit events.
    pub audit_days: u32,
    /// Days to keep scheduling inbox items.
    pub scheduling_inbox_days: u32,
    /// Days between the deletion of a calendar and its purge.
    pub deleted_calendar_days: u32,
    /// Days between the deletion of a principal and its purge (`?purge=true` purges immediately).
    pub principal_purge_days: u32,
    /// Hours to keep idempotency keys.
    pub idempotency_hours: u32,
    /// Days to keep OAuth states.
    pub oauth_state_days: u32,
    /// Days to keep an RSVP token after it expired or was revoked, before the cleanup worker removes it.
    pub rsvp_token_days: u32,
    /// Days to keep the delivery records of webhooks (the status of each attempt to deliver an event to a subscription).
    pub webhook_delivery_days: u32,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            outbox_done_days: 7,
            outbox_dead_days: 30,
            collection_changes_days: 90,
            audit_days: 365,
            scheduling_inbox_days: 30,
            deleted_calendar_days: 30,
            principal_purge_days: 30,
            idempotency_hours: 24,
            oauth_state_days: 1,
            rsvp_token_days: 30,
            webhook_delivery_days: 30,
        }
    }
}

impl RetentionConfig {
    /// Checks that every period is positive.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] naming the first zero period.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let periods: [(&'static str, u32); 11] = [
            ("outbox_done_days", self.outbox_done_days),
            ("outbox_dead_days", self.outbox_dead_days),
            ("collection_changes_days", self.collection_changes_days),
            ("audit_days", self.audit_days),
            ("scheduling_inbox_days", self.scheduling_inbox_days),
            ("deleted_calendar_days", self.deleted_calendar_days),
            ("principal_purge_days", self.principal_purge_days),
            ("idempotency_hours", self.idempotency_hours),
            ("oauth_state_days", self.oauth_state_days),
            ("rsvp_token_days", self.rsvp_token_days),
            ("webhook_delivery_days", self.webhook_delivery_days),
        ];
        for (key, value) in periods {
            positive("retention", key, value.into())?;
        }
        Ok(())
    }
}

/// The `[outbox]` table: the dispatcher of the transactional outbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct OutboxConfig {
    /// The most messages one dispatcher claims at a time.
    pub batch_size: u32,
    /// How long a claim lasts before another dispatcher may take the message over.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub lease: Duration,
    /// After this many attempts a message goes dead.
    pub max_attempts: u32,
    /// The delay before the second attempt; it doubles with every further attempt.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub backoff_base: Duration,
    /// The longest delay between two attempts.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub backoff_max: Duration,
    /// The most webhook subscriptions one tenant may have. Every event is expanded into one delivery per matching
    /// subscription, so the limit bounds the work one event costs the shared dispatcher.
    pub max_webhooks_per_tenant: u32,
    /// How many handlers of one pass run at the same time. A claim lasts `lease` and every handler of the pass
    /// has to be done before 80 % of it has passed, so `concurrency` times the time a handler takes bounds what
    /// one pass can do; records that do not get a turn in time are put back without using an attempt.
    pub concurrency: u32,
    /// How long the dispatcher sleeps when a pass found nothing to do.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub poll_interval: Duration,
}

impl Default for OutboxConfig {
    fn default() -> Self {
        Self {
            batch_size: 25,
            lease: Duration::from_mins(1),
            max_attempts: 12,
            backoff_base: Duration::from_secs(30),
            backoff_max: Duration::from_hours(1),
            max_webhooks_per_tenant: 50,
            concurrency: 8,
            poll_interval: Duration::from_secs(2),
        }
    }
}

impl OutboxConfig {
    /// Checks that every value is usable.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] naming the first unusable key.
    pub fn validate(&self) -> Result<(), ConfigError> {
        positive("outbox", "batch_size", self.batch_size.into())?;
        positive("outbox", "max_attempts", self.max_attempts.into())?;
        // The limit is checked by listing one more subscription than it allows, in one page.
        if !(1..1000).contains(&self.max_webhooks_per_tenant) {
            return Err(ConfigError::new(
                "outbox",
                "max_webhooks_per_tenant",
                "must be between 1 and 999",
            ));
        }
        positive("outbox", "concurrency", self.concurrency.into())?;
        if self.concurrency > 256 {
            return Err(ConfigError::new("outbox", "concurrency", "must not exceed 256"));
        }
        if self.poll_interval.is_zero() {
            return Err(ConfigError::new("outbox", "poll_interval", "must be greater than zero"));
        }
        if self.lease.is_zero() {
            return Err(ConfigError::new("outbox", "lease", "must be greater than zero"));
        }
        if self.backoff_base.is_zero() {
            return Err(ConfigError::new("outbox", "backoff_base", "must be greater than zero"));
        }
        if self.backoff_base > self.backoff_max {
            return Err(ConfigError::new(
                "outbox",
                "backoff_base",
                "must not exceed backoff_max",
            ));
        }
        Ok(())
    }
}

/// The `[feeds]` table: subscription feeds (PLAN 2.13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct FeedsConfig {
    /// The refresh interval advertised to subscribers (`REFRESH-INTERVAL` and `X-PUBLISHED-TTL`), as an
    /// iCalendar duration.
    pub refresh_interval: EventDuration,
    /// How many days before the start of the current UTC day a feed starts. The window is anchored at the start of the
    /// UTC day, not at the instant of the request, so the entity tag of a feed can be known without rendering it: a feed
    /// changes at 00:00 UTC for the passing of time alone.
    pub window_past_days: u32,
    /// How many days after the start of the current UTC day a feed ends.
    pub window_future_days: u32,
    /// The most objects one feed holds; a feed that needs more is cut after them (and logged).
    pub max_objects: u32,
    /// The most bytes of calendar data one feed holds; a feed that needs more is cut (and logged).
    pub max_bytes: u64,
}

impl Default for FeedsConfig {
    fn default() -> Self {
        Self {
            refresh_interval: default_refresh_interval(),
            window_past_days: 90,
            window_future_days: 365,
            max_objects: 20_000,
            max_bytes: 32 * 1024 * 1024,
        }
    }
}

/// `PT15M`.
#[expect(
    clippy::expect_used,
    reason = "PT15M is a valid duration literal; the unit tests parse every default"
)]
fn default_refresh_interval() -> EventDuration {
    EventDuration::parse("PT15M").expect("PT15M is a valid iCalendar duration")
}

impl FeedsConfig {
    /// Checks that every value is usable.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] naming the first unusable key.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.refresh_interval.seconds() < 60 {
            return Err(ConfigError::new(
                "feeds",
                "refresh_interval",
                "must be at least one minute (for example PT15M)",
            ));
        }
        positive("feeds", "window_future_days", self.window_future_days.into())?;
        positive("feeds", "max_objects", self.max_objects.into())?;
        positive("feeds", "max_bytes", self.max_bytes)
    }
}

/// The longest an account may take (`[providers.sync] timeout`): a pass of the sync worker must end before `/readyz` calls the
/// worker stalled ([`STALL_LIMIT`]), and it never starts an account after [`PASS_BUDGET`]. A pass is then over after the budget,
/// the longest pull and the margin for the transactions that claim and settle accounts.
const MAX_SYNC_TIMEOUT: Duration = Duration::from_secs(150);

const _: () = assert!(
    PASS_BUDGET.as_secs() + MAX_SYNC_TIMEOUT.as_secs() + STALL_MARGIN.as_secs() <= STALL_LIMIT.as_secs(),
    "a pass of the sync worker must end before the worker is called stalled"
);

/// The `[providers.sync]` table: how the sync engine pulls the calendars of connected provider accounts into their mirror
/// calendars (PLAN 4.2). The tables of the providers themselves (`[providers.google]`, `[providers.microsoft]`) hold the
/// OAuth client and the window of the import; this one holds what is true of every provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ProviderSyncConfig {
    /// How long an account waits between two pulls.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub interval: Duration,
    /// How long the sync worker sleeps when no account is due. A newly connected account is pulled at the next pass.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub poll_interval: Duration,
    /// The most accounts one pass pulls; the rest wait for the next pass.
    pub batch_size: u32,
    /// How many accounts of one pass are pulled at the same time.
    pub concurrency: u32,
    /// The longest a single pull may take. One that takes longer is abandoned without advancing the cursor, and the account is
    /// tried again after the claim on it has run out. At most two and a half minutes.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub timeout: Duration,
    /// The longest wait after failed pulls. The wait starts at a third of `interval` and doubles with every failure in a row.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub backoff_max: Duration,
}

impl Default for ProviderSyncConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_mins(15),
            poll_interval: Duration::from_mins(1),
            batch_size: 8,
            concurrency: 4,
            timeout: Duration::from_secs(90),
            backoff_max: Duration::from_hours(1),
        }
    }
}

impl ProviderSyncConfig {
    /// Checks that every value is usable.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] naming the first unusable key.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let section = "providers.sync";
        for (key, value) in [
            ("interval", self.interval),
            ("poll_interval", self.poll_interval),
            ("timeout", self.timeout),
            ("backoff_max", self.backoff_max),
        ] {
            if value.is_zero() {
                return Err(ConfigError::new(section, key, "must be greater than zero"));
            }
        }
        if self.interval < Duration::from_mins(1) {
            return Err(ConfigError::new(
                section,
                "interval",
                "must be at least one minute: the providers throttle clients that pull more often",
            ));
        }
        positive(section, "batch_size", self.batch_size.into())?;
        positive(section, "concurrency", self.concurrency.into())?;
        if self.concurrency > 32 || self.concurrency > self.batch_size {
            return Err(ConfigError::new(
                section,
                "concurrency",
                "must not exceed 32 or batch_size",
            ));
        }
        if self.timeout > MAX_SYNC_TIMEOUT {
            return Err(ConfigError::new(
                section,
                "timeout",
                "must not exceed 2m30s, so that a pass ends before the worker is called stalled",
            ));
        }
        if self.backoff_max < self.interval {
            return Err(ConfigError::new(
                section,
                "backoff_max",
                "must not be less than interval",
            ));
        }
        Ok(())
    }
}

/// The validated configuration the application layer runs with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppConfig {
    /// Outgoing mail policy.
    pub mail: MailConfig,
    /// Scheduling ceilings.
    pub scheduling: SchedulingConfig,
    /// Calendar sharing.
    pub sharing: SharingConfig,
    /// Retention periods.
    pub retention: RetentionConfig,
    /// The outbox dispatcher.
    pub outbox: OutboxConfig,
    /// Subscription feeds.
    pub feeds: FeedsConfig,
    /// The sync engine of the provider accounts (`[providers.sync]`).
    pub provider_sync: ProviderSyncConfig,
    /// The longest lifetime of a token with `mcp:*` scopes, in days (`security.max_mcp_token_days`).
    pub max_mcp_token_days: u32,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            mail: MailConfig::default(),
            scheduling: SchedulingConfig::default(),
            sharing: SharingConfig::default(),
            retention: RetentionConfig::default(),
            outbox: OutboxConfig::default(),
            feeds: FeedsConfig::default(),
            provider_sync: ProviderSyncConfig::default(),
            max_mcp_token_days: 90,
        }
    }
}

impl AppConfig {
    /// Validates every section.
    ///
    /// # Errors
    ///
    /// Returns the first [`ConfigError`] of any section.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.mail.validate()?;
        self.scheduling.validate()?;
        self.retention.validate()?;
        self.outbox.validate()?;
        self.feeds.validate()?;
        self.provider_sync.validate()?;
        positive("security", "max_mcp_token_days", self.max_mcp_token_days.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_the_plan_values_and_valid() {
        let config = AppConfig::default();
        config.validate().unwrap();
        assert_eq!(config.scheduling.max_sync_internal_attendees, 50);
        assert_eq!(config.scheduling.external_per_event, 50);
        assert!(!config.scheduling.inbound_itip.enabled);
        assert!(config.scheduling.inbound_itip.require_dmarc_pass);
        assert!(config.sharing.enabled);
        assert_eq!(config.mail.from_mode, MailFromMode::Service);
        assert_eq!(config.retention.outbox_done_days, 7);
        assert_eq!(config.retention.outbox_dead_days, 30);
        assert_eq!(config.retention.collection_changes_days, 90);
        assert_eq!(config.retention.audit_days, 365);
        assert_eq!(config.retention.scheduling_inbox_days, 30);
        assert_eq!(config.retention.deleted_calendar_days, 30);
        assert_eq!(config.retention.principal_purge_days, 30);
        assert_eq!(config.retention.idempotency_hours, 24);
        assert_eq!(config.retention.oauth_state_days, 1);
        assert_eq!(config.outbox.lease, Duration::from_mins(1));
        assert_eq!(config.outbox.max_attempts, 12);
        assert_eq!(config.outbox.backoff_base, Duration::from_secs(30));
        assert_eq!(config.outbox.backoff_max, Duration::from_hours(1));
        assert_eq!(config.feeds.refresh_interval.as_str(), "PT15M");
        assert_eq!(config.feeds.window_past_days, 90);
        assert_eq!(config.feeds.window_future_days, 365);
        assert_eq!(config.feeds.max_objects, 20_000);
        assert_eq!(config.feeds.max_bytes, 32 * 1024 * 1024);
        assert_eq!(config.max_mcp_token_days, 90);
        let sync = &config.provider_sync;
        assert_eq!(sync.interval, Duration::from_mins(15));
        assert_eq!(sync.poll_interval, Duration::from_mins(1));
        assert_eq!((sync.batch_size, sync.concurrency), (8, 4));
        assert_eq!(sync.timeout, Duration::from_secs(90));
        assert_eq!(sync.backoff_max, Duration::from_hours(1));
    }

    #[test]
    fn sections_deserialize_with_defaults_and_reject_unknown_keys() {
        let outbox: OutboxConfig = serde_json::from_str(r#"{"lease": "2m", "batch_size": 5}"#).unwrap();
        assert_eq!(outbox.lease, Duration::from_mins(2));
        assert_eq!(outbox.batch_size, 5);
        assert_eq!(outbox.max_attempts, 12);
        let mail: MailConfig = serde_json::from_str(
            r#"{"from_mode": "organizer", "redirect_all_to": "Staging@Example.org", "allowed_recipient_domains": ["example.org"]}"#,
        )
        .unwrap();
        assert_eq!(mail.from_mode, MailFromMode::Organizer);
        assert_eq!(mail.redirect_all_to.unwrap().as_str(), "staging@example.org");
        let feeds: FeedsConfig = serde_json::from_str(r#"{"refresh_interval": "PT1H"}"#).unwrap();
        assert_eq!(feeds.refresh_interval.seconds(), 3600);
        for text in [r#"{"batch_sise": 5}"#, r#"{"lease": "soon"}"#] {
            assert!(serde_json::from_str::<OutboxConfig>(text).is_err(), "{text}");
        }
        assert!(serde_json::from_str::<SchedulingConfig>(r#"{"inbound_itip": {"enabled": true, "x": 1}}"#).is_err());
        assert!(serde_json::from_str::<SharingConfig>(r#"{"enabled": false}"#).is_ok());
        assert!(serde_json::from_str::<RetentionConfig>(r#"{"audit_days": -1}"#).is_err());
    }

    #[test]
    fn validation_names_the_offending_key() {
        let outbox = OutboxConfig {
            batch_size: 0,
            ..OutboxConfig::default()
        };
        let error = outbox.validate().unwrap_err();
        assert_eq!((error.section(), error.key()), ("outbox", "batch_size"));
        assert_eq!(
            error.to_string(),
            "invalid configuration `outbox.batch_size`: must be greater than zero"
        );
        let inverted = OutboxConfig {
            backoff_base: Duration::from_hours(2),
            ..OutboxConfig::default()
        };
        assert_eq!(inverted.validate().unwrap_err().key(), "backoff_base");
        let no_lease = OutboxConfig {
            lease: Duration::ZERO,
            ..OutboxConfig::default()
        };
        assert_eq!(no_lease.validate().unwrap_err().key(), "lease");
        for bad in [0, 1000] {
            let webhooks = OutboxConfig {
                max_webhooks_per_tenant: bad,
                ..OutboxConfig::default()
            };
            assert_eq!(
                webhooks.validate().unwrap_err().key(),
                "max_webhooks_per_tenant",
                "{bad}"
            );
        }
        assert_eq!(OutboxConfig::default().max_webhooks_per_tenant, 50);
        for bad in [0, 257] {
            let workers = OutboxConfig {
                concurrency: bad,
                ..OutboxConfig::default()
            };
            assert_eq!(workers.validate().unwrap_err().key(), "concurrency", "{bad}");
        }
        let no_polling = OutboxConfig {
            poll_interval: Duration::ZERO,
            ..OutboxConfig::default()
        };
        assert_eq!(no_polling.validate().unwrap_err().key(), "poll_interval");
        let defaults = OutboxConfig::default();
        assert_eq!(
            (defaults.concurrency, defaults.poll_interval),
            (8, Duration::from_secs(2))
        );
        let scheduling = SchedulingConfig {
            external_per_event: 500,
            ..SchedulingConfig::default()
        };
        assert_eq!(scheduling.validate().unwrap_err().key(), "external_per_event");
        let retention = RetentionConfig {
            audit_days: 0,
            ..RetentionConfig::default()
        };
        assert_eq!(retention.validate().unwrap_err().key(), "audit_days");
        let feeds = FeedsConfig {
            refresh_interval: EventDuration::parse("PT30S").unwrap(),
            ..FeedsConfig::default()
        };
        assert_eq!(feeds.validate().unwrap_err().key(), "refresh_interval");
        let mail = MailConfig {
            rate_limit_per_minute: 0,
            ..MailConfig::default()
        };
        assert_eq!(mail.validate().unwrap_err().key(), "rate_limit_per_minute");
        let app = AppConfig {
            max_mcp_token_days: 0,
            ..AppConfig::default()
        };
        assert_eq!(app.validate().unwrap_err().section(), "security");
    }

    #[test]
    fn the_sync_table_is_checked_key_by_key() {
        let key_of = |config: ProviderSyncConfig| config.validate().unwrap_err().key();
        ProviderSyncConfig::default().validate().unwrap();
        let sync = ProviderSyncConfig::default;
        assert_eq!(
            key_of(ProviderSyncConfig {
                interval: Duration::ZERO,
                ..sync()
            }),
            "interval"
        );
        assert_eq!(
            key_of(ProviderSyncConfig {
                interval: Duration::from_secs(30),
                ..sync()
            }),
            "interval",
            "the providers throttle clients that pull more often than once a minute"
        );
        assert_eq!(
            key_of(ProviderSyncConfig {
                poll_interval: Duration::ZERO,
                ..sync()
            }),
            "poll_interval"
        );
        assert_eq!(
            key_of(ProviderSyncConfig {
                batch_size: 0,
                ..sync()
            }),
            "batch_size"
        );
        for (concurrency, batch_size) in [(0, 8), (33, 64), (9, 8)] {
            assert_eq!(
                key_of(ProviderSyncConfig {
                    batch_size,
                    concurrency,
                    ..sync()
                }),
                "concurrency",
                "{concurrency} of {batch_size}"
            );
        }
        assert_eq!(
            key_of(ProviderSyncConfig {
                timeout: Duration::from_mins(4),
                ..sync()
            }),
            "timeout"
        );
        assert_eq!(
            key_of(ProviderSyncConfig {
                backoff_max: Duration::from_mins(5),
                ..sync()
            }),
            "backoff_max",
            "the backoff cannot be shorter than the interval"
        );
        let error = ProviderSyncConfig {
            batch_size: 0,
            ..sync()
        }
        .validate()
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid configuration `providers.sync.batch_size`: must be greater than zero"
        );
        let parsed: ProviderSyncConfig = serde_json::from_str(r#"{"interval": "30m", "concurrency": 2}"#).unwrap();
        assert_eq!((parsed.interval, parsed.concurrency), (Duration::from_mins(30), 2));
        assert!(serde_json::from_str::<ProviderSyncConfig>(r#"{"interval": "30m", "poll": "1m"}"#).is_err());
    }

    #[test]
    fn every_section_has_a_json_schema() {
        for schema in [
            schemars::schema_for!(MailConfig),
            schemars::schema_for!(SchedulingConfig),
            schemars::schema_for!(SharingConfig),
            schemars::schema_for!(RetentionConfig),
            schemars::schema_for!(OutboxConfig),
            schemars::schema_for!(FeedsConfig),
            schemars::schema_for!(ProviderSyncConfig),
        ] {
            assert_eq!(schema.as_value()["type"], "object");
            assert_eq!(schema.as_value()["additionalProperties"], false);
        }
        let outbox = schemars::schema_for!(OutboxConfig);
        assert_eq!(outbox.as_value()["properties"]["lease"]["type"], "string");
    }
}
