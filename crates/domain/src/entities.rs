//! Entities of the data model: tenants, principals, calendars, bindings, grants, objects and credentials.
//!
//! The structs mirror the tables of PLAN 2.4 column by column (timestamps are UTC, `version` is the optimistic
//! concurrency counter behind ETags and `If-Match`). They are plain data: storage adapters map rows to and from
//! them and the application layer changes them. Structs holding sealed or hashed secrets implement `Debug` by
//! hand and never print those bytes (`ENGINEERING_RULES` R6).

use core::fmt;

use chrono::{DateTime, Utc};

use crate::events::EventType;
use crate::ids::{
    BindingId, CalendarId, CredentialId, ExternalAccountId, GrantId, InboxItemId, NotificationId, ObjectId,
    PrincipalId, TenantId, TokenId, WebhookId,
};
use crate::keys::{
    CalendarSlug, CalendarUserAddress, ContentHash, DomainName, ETag, Email, ExternalKey, Locale, ObjectUri,
    PrincipalName, ScheduleTag, TenantSlug, TimeZoneName, Uid,
};
use crate::scope::{ScopeSet, TokenKind};
use crate::settings::TenantSettings;
use crate::vocab::{Classification, ComponentKind, PartStat, Transparency};

text_enum!(
    /// Lifecycle status of a tenant.
    TenantStatus [] {
        /// The tenant is in service.
        Active => "active",
        /// Logins and tokens of the tenant are refused; data is kept.
        Suspended => "suspended",
    }
);

text_enum!(
    /// What a principal represents.
    PrincipalKind [] {
        /// A person who logs in.
        User => "user",
        /// A group that owns calendars and has members.
        Group => "group",
        /// A bookable resource (room, equipment) with its own calendar.
        Resource => "resource",
        /// A service account used by integrations.
        Service => "service",
    }
);

text_enum!(
    /// Lifecycle status of a principal.
    PrincipalStatus [] {
        /// Normal operation.
        Active => "active",
        /// Authentication is refused; data is kept.
        Suspended => "suspended",
        /// Hidden after deletion until the purge removes it.
        Deleted => "deleted",
    }
);

text_enum!(
    /// The kind of a calendar (`calendars.kind`).
    CalendarKind [] {
        /// The default calendar of a user (one per user).
        Personal => "personal",
        /// A calendar owned by a group; members get the tenant's default group access.
        Group => "group",
        /// A calendar written through the API only; read-only for users.
        Managed => "managed",
        /// A calendar a user created.
        User => "user",
        /// A read-only mirror of an external provider calendar.
        Mirror => "mirror",
    }
);

text_enum!(
    /// The access a grant confers (`calendar_grants.access`).
    GrantAccess [] {
        /// Read events.
        Read => "read",
        /// Read and write events.
        ReadWrite => "read_write",
        /// Read, write, share and rename.
        Admin => "admin",
    }
);

text_enum!(
    /// The state of a grant.
    GrantStatus [] {
        /// Offered, not yet answered; confers nothing.
        Pending => "pending",
        /// Accepted by the grantee; confers its access.
        Accepted => "accepted",
        /// Declined by the grantee; confers nothing.
        Declined => "declined",
    }
);

text_enum!(
    /// Where a grant came from; the last write wins between API and DAV.
    GrantSource [] {
        /// Created through the management API.
        Api => "api",
        /// Created through CalendarServer sharing from a client.
        Share => "share",
    }
);

text_enum!(
    /// The type of a CalendarServer notification.
    NotificationKind [] {
        /// A share invitation for the recipient.
        Invite => "invite",
        /// The reply of a sharee, delivered to the owner.
        InviteReply => "invite_reply",
    }
);

text_enum!(
    /// What a feed token exposes.
    FeedMode [] {
        /// Full event details (private and confidential events stay busy-only for non-owners).
        Full => "full",
        /// Only busy time.
        Busy => "busy",
    }
);

text_enum!(
    /// The state of an external provider account.
    ExternalAccountStatus [] {
        /// Syncing normally.
        Active => "active",
        /// The last sync failed; see `last_error`.
        Error => "error",
        /// Disabled by an administrator or after revoked access.
        Disabled => "disabled",
    }
);

/// A tenant.
#[derive(Debug, Clone, PartialEq)]
pub struct Tenant {
    /// Tenant id.
    pub id: TenantId,
    /// Immutable URL-safe identifier.
    pub slug: TenantSlug,
    /// Display name.
    pub display_name: String,
    /// Domain used for `name@login_domain` logins.
    pub login_domain: Option<DomainName>,
    /// Lifecycle status.
    pub status: TenantStatus,
    /// Typed settings.
    pub settings: TenantSettings,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last modification time.
    pub updated_at: DateTime<Utc>,
    /// Optimistic concurrency counter.
    pub version: i64,
}

/// A principal: user, group, resource or service.
#[derive(Debug, Clone, PartialEq)]
pub struct Principal {
    /// Principal id.
    pub id: PrincipalId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// What the principal represents.
    pub kind: PrincipalKind,
    /// Immutable login local-part.
    pub name: PrincipalName,
    /// Display name.
    pub display_name: String,
    /// Primary e-mail address.
    pub email: Option<Email>,
    /// Preferred locale.
    pub locale: Option<Locale>,
    /// Preferred time zone.
    pub timezone: Option<TimeZoneName>,
    /// Identifier in an external system, unique per tenant.
    pub external_ref: Option<String>,
    /// Lifecycle status.
    pub status: PrincipalStatus,
    /// When the principal was deleted (hidden), if it was.
    pub deleted_at: Option<DateTime<Utc>>,
    /// Bumped to invalidate cached credential verifications.
    pub credential_generation: i32,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last modification time.
    pub updated_at: DateTime<Utc>,
    /// Optimistic concurrency counter.
    pub version: i64,
}

/// A calendar.
#[derive(Debug, Clone, PartialEq)]
pub struct Calendar {
    /// Calendar id.
    pub id: CalendarId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Owning principal (a user, a group, a resource or a service).
    pub owner_id: PrincipalId,
    /// Immutable slug, unique per owner among live calendars.
    pub slug: CalendarSlug,
    /// The kind of calendar.
    pub kind: CalendarKind,
    /// Display name.
    pub display_name: String,
    /// Description.
    pub description: Option<String>,
    /// Color as `#RRGGBB` or `#RRGGBBAA`.
    pub color: Option<String>,
    /// Sort order hint for clients.
    pub sort_order: i32,
    /// Component types the calendar accepts (`supported-calendar-component-set`).
    pub components: Vec<ComponentKind>,
    /// `VTIMEZONE` text of the default time zone (`calendar-timezone`).
    pub timezone_ics: Option<String>,
    /// Sequence number of the last change (`sync_seq`).
    pub sync_seq: i64,
    /// Oldest sequence number that sync tokens can still resume from.
    pub sync_min_seq: i64,
    /// Epoch of the sync tokens; changes after a restore.
    pub sync_epoch: uuid::Uuid,
    /// When the calendar was soft-deleted, if it was.
    pub deleted_at: Option<DateTime<Utc>>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last modification time.
    pub updated_at: DateTime<Utc>,
    /// Optimistic concurrency counter.
    pub version: i64,
}

/// A principal's view of a calendar; `None` overrides fall back to the calendar's values.
#[derive(Debug, Clone, PartialEq)]
pub struct Binding {
    /// Binding id.
    pub id: BindingId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// The principal whose home lists the binding.
    pub principal_id: PrincipalId,
    /// The bound calendar.
    pub calendar_id: CalendarId,
    /// Slug of the collection in the principal's home.
    pub slug: CalendarSlug,
    /// Display name override.
    pub display_name: Option<String>,
    /// Color override.
    pub color: Option<String>,
    /// Sort order override.
    pub sort_order: Option<i32>,
    /// Override of `schedule-calendar-transp`.
    pub schedule_transp: Option<Transparency>,
    /// Hidden bindings are not listed in the principal's home.
    pub hidden: bool,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last modification time.
    pub updated_at: DateTime<Utc>,
    /// Optimistic concurrency counter.
    pub version: i64,
}

/// A grant of access to a calendar for a user, a group or a service principal.
#[derive(Debug, Clone, PartialEq)]
pub struct Grant {
    /// Grant id.
    pub id: GrantId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// The shared calendar.
    pub calendar_id: CalendarId,
    /// The user, group or service principal that is granted access.
    pub grantee_id: PrincipalId,
    /// The access level.
    pub access: GrantAccess,
    /// Pending, accepted or declined.
    pub status: GrantStatus,
    /// Whether the API or a client created it.
    pub source: GrantSource,
    /// Whether the calendar is **required** for the people the grant reaches: a member of the grantee group (or the
    /// grantee itself) cannot remove the calendar from their own home, because an accepted grant with this flag makes
    /// `DELETE` of the bound collection a refusal (403, `DAV:need-privileges` naming `DAV:unbind`) instead of hiding the
    /// binding. Optional grants (the default, and every grant a client creates) leave that to the sharee.
    pub required: bool,
    /// UID of the CalendarServer invitation.
    pub invite_uid: Option<Uid>,
    /// Summary shown in the invitation.
    pub summary: Option<String>,
    /// Common name of the sharee shown to the owner.
    pub common_name: Option<String>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last modification time.
    pub updated_at: DateTime<Utc>,
    /// Optimistic concurrency counter.
    pub version: i64,
}

/// A calendar object resource as stored: the client's bytes verbatim plus the extracted index columns.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredObject {
    /// Object id.
    pub id: ObjectId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// The containing calendar.
    pub calendar_id: CalendarId,
    /// The calendar's owner, denormalized for per-owner scheduling uniqueness.
    pub owner_id: PrincipalId,
    /// Decoded resource name.
    pub uri: ObjectUri,
    /// iCalendar UID, unique per calendar.
    pub uid: Uid,
    /// Strong entity tag of `data`.
    pub etag: ETag,
    /// Schedule-Tag of scheduling object resources.
    pub schedule_tag: Option<ScheduleTag>,
    /// Hash ignoring volatile properties.
    pub content_hash: ContentHash,
    /// The main component type.
    pub component: ComponentKind,
    /// The iCalendar text, verbatim.
    pub data: String,
    /// Size of `data` in bytes.
    pub size: u64,
    /// Start of the first instance in UTC; `None` for undated components.
    pub first_start: Option<DateTime<Utc>>,
    /// End of the last instance in UTC; `None` means unbounded (stored as infinity).
    pub last_end: Option<DateTime<Utc>>,
    /// Whether the object recurs.
    pub is_recurring: bool,
    /// Whether the object has an organizer and attendees.
    pub is_scheduling: bool,
    /// The organizer's address.
    pub organizer_address: Option<CalendarUserAddress>,
    /// The `SEQUENCE` of the master component.
    pub sequence: i32,
    /// The `CLASS` of the master component.
    pub class: Classification,
    /// Caller-chosen key (management API).
    pub external_key: Option<ExternalKey>,
    /// Marker of the provider that imported the object, for mirror calendars.
    pub origin: Option<String>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last modification time.
    pub updated_at: DateTime<Utc>,
    /// Optimistic concurrency counter.
    pub version: i64,
}

/// A CalendarServer notification in a principal's notification collection.
#[derive(Debug, Clone, PartialEq)]
pub struct Notification {
    /// Notification id.
    pub id: NotificationId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// The recipient.
    pub principal_id: PrincipalId,
    /// Decoded resource name.
    pub uri: ObjectUri,
    /// UID of the invitation the notification refers to.
    pub uid: Uid,
    /// Strong entity tag of `body_xml`.
    pub etag: ETag,
    /// Invitation or invitation reply.
    pub kind: NotificationKind,
    /// The notification XML as served.
    pub body_xml: String,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last modification time.
    pub updated_at: DateTime<Utc>,
    /// Optimistic concurrency counter.
    pub version: i64,
}

/// An item in a principal's scheduling inbox.
#[derive(Debug, Clone, PartialEq)]
pub struct InboxItem {
    /// Inbox item id.
    pub id: InboxItemId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// The recipient.
    pub principal_id: PrincipalId,
    /// Decoded resource name.
    pub uri: ObjectUri,
    /// Strong entity tag of `data`.
    pub etag: ETag,
    /// The iTIP message as iCalendar text.
    pub data: String,
    /// Quarantined items are kept for inspection and never shown to clients.
    pub quarantined: bool,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last modification time.
    pub updated_at: DateTime<Utc>,
    /// Optimistic concurrency counter.
    pub version: i64,
}

/// Writes a redacted placeholder for secret bytes.
fn redacted(bytes: &[u8]) -> impl fmt::Debug {
    struct Redacted(usize);
    impl fmt::Debug for Redacted {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "<{} bytes redacted>", self.0)
        }
    }
    Redacted(bytes.len())
}

/// A per-device DAV app password (only its keyed hash is stored).
#[derive(Clone, PartialEq, Eq)]
pub struct AppPassword {
    /// Credential id.
    pub id: CredentialId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// The principal it authenticates.
    pub principal_id: PrincipalId,
    /// Label chosen by the user, for example the device name.
    pub label: String,
    /// The first two groups of the password, used to find the row.
    pub prefix: String,
    /// HMAC-SHA256 of the secret under the pepper `pepper_kid`.
    pub hash: Vec<u8>,
    /// Id of the pepper key that produced `hash`.
    pub pepper_kid: String,
    /// Last use, flushed at most every 15 minutes.
    pub last_used_at: Option<DateTime<Utc>>,
    /// Revocation time.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last modification time.
    pub updated_at: DateTime<Utc>,
    /// Optimistic concurrency counter.
    pub version: i64,
}

impl fmt::Debug for AppPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppPassword")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("principal_id", &self.principal_id)
            .field("label", &self.label)
            .field("prefix", &self.prefix)
            .field("hash", &redacted(&self.hash))
            .field("pepper_kid", &self.pepper_kid)
            .field("last_used_at", &self.last_used_at)
            .field("revoked_at", &self.revoked_at)
            .finish_non_exhaustive()
    }
}

/// An API token (only its keyed hash is stored).
#[derive(Clone, PartialEq, Eq)]
pub struct ApiToken {
    /// Token id.
    pub id: TokenId,
    /// Owning tenant; `None` only for system tokens.
    pub tenant_id: Option<TenantId>,
    /// System, tenant or principal token.
    pub kind: TokenKind,
    /// The principal a principal token acts as.
    pub principal_id: Option<PrincipalId>,
    /// Label chosen at creation.
    pub label: String,
    /// The scopes the token carries.
    pub scopes: ScopeSet,
    /// The 12 character prefix used to find the row.
    pub prefix: String,
    /// HMAC-SHA256 of the secret under the pepper `pepper_kid`.
    pub hash: Vec<u8>,
    /// Id of the pepper key that produced `hash`.
    pub pepper_kid: String,
    /// Expiry; required for tokens with `mcp:*` scopes.
    pub expires_at: Option<DateTime<Utc>>,
    /// The token that minted this one, if any.
    pub created_by: Option<TokenId>,
    /// Origins allowed to call the API with this token from a browser.
    pub allowed_origins: Vec<String>,
    /// Last use, flushed at most every 15 minutes.
    pub last_used_at: Option<DateTime<Utc>>,
    /// Revocation time.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last modification time.
    pub updated_at: DateTime<Utc>,
    /// Optimistic concurrency counter.
    pub version: i64,
}

impl fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiToken")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("kind", &self.kind)
            .field("principal_id", &self.principal_id)
            .field("label", &self.label)
            .field("scopes", &self.scopes)
            .field("prefix", &self.prefix)
            .field("hash", &redacted(&self.hash))
            .field("pepper_kid", &self.pepper_kid)
            .field("expires_at", &self.expires_at)
            .field("revoked_at", &self.revoked_at)
            .finish_non_exhaustive()
    }
}

/// A token in a subscription feed URL (only its keyed hash is stored).
#[derive(Clone, PartialEq, Eq)]
pub struct FeedToken {
    /// Token id.
    pub id: TokenId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// The principal whose access the feed is rendered with.
    pub principal_id: PrincipalId,
    /// Full details or busy time only.
    pub mode: FeedMode,
    /// The calendars the feed contains.
    pub calendar_ids: Vec<CalendarId>,
    /// The 12 character prefix used to find the row.
    pub prefix: String,
    /// HMAC-SHA256 of the secret under the pepper `pepper_kid`.
    pub hash: Vec<u8>,
    /// Id of the pepper key that produced `hash`.
    pub pepper_kid: String,
    /// Revocation time.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last modification time.
    pub updated_at: DateTime<Utc>,
    /// Optimistic concurrency counter.
    pub version: i64,
}

impl fmt::Debug for FeedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FeedToken")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("principal_id", &self.principal_id)
            .field("mode", &self.mode)
            .field("calendar_ids", &self.calendar_ids)
            .field("prefix", &self.prefix)
            .field("hash", &redacted(&self.hash))
            .field("revoked_at", &self.revoked_at)
            .finish_non_exhaustive()
    }
}

/// A token in an RSVP link (only its keyed hash is stored).
#[derive(Clone, PartialEq, Eq)]
pub struct RsvpToken {
    /// Token id.
    pub id: TokenId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// The invitation the link answers.
    pub object_id: ObjectId,
    /// The attendee the link was issued to.
    pub attendee_address: CalendarUserAddress,
    /// The 12 character prefix used to find the row.
    pub prefix: String,
    /// Keyed hash of the secret.
    pub hash: Vec<u8>,
    /// Id of the key that produced `hash`.
    pub pepper_kid: String,
    /// Expiry: the end of the last instance plus seven days, at most one year.
    pub expires_at: DateTime<Utc>,
    /// Revocation time (attendee removed, event cancelled or deleted).
    pub revoked_at: Option<DateTime<Utc>>,
    /// Last use.
    pub last_used_at: Option<DateTime<Utc>>,
    /// The last answer given through the link.
    pub last_response: Option<PartStat>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last modification time.
    pub updated_at: DateTime<Utc>,
    /// Optimistic concurrency counter.
    pub version: i64,
}

impl fmt::Debug for RsvpToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsvpToken")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("object_id", &self.object_id)
            .field("prefix", &self.prefix)
            .field("hash", &redacted(&self.hash))
            .field("expires_at", &self.expires_at)
            .field("revoked_at", &self.revoked_at)
            .finish_non_exhaustive()
    }
}

/// An account at an external calendar provider that is mirrored into a calendar.
#[derive(Clone, PartialEq)]
pub struct ExternalAccount {
    /// External account id.
    pub id: ExternalAccountId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// The principal who connected the account.
    pub principal_id: PrincipalId,
    /// Provider name, for example `google`.
    pub provider: String,
    /// The provider's reference for the account.
    pub account_ref: String,
    /// OAuth tokens, sealed with the secret sealer.
    pub sealed_tokens: Vec<u8>,
    /// The mirror calendar the events are imported into.
    pub mirror_calendar_id: Option<CalendarId>,
    /// Provider-specific sync cursor state.
    pub sync_state: serde_json::Value,
    /// Account state.
    pub status: ExternalAccountStatus,
    /// The last sync error, for operators.
    pub last_error: Option<String>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last modification time.
    pub updated_at: DateTime<Utc>,
    /// Optimistic concurrency counter.
    pub version: i64,
}

impl fmt::Debug for ExternalAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalAccount")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("principal_id", &self.principal_id)
            .field("provider", &self.provider)
            .field("account_ref", &self.account_ref)
            .field("sealed_tokens", &redacted(&self.sealed_tokens))
            .field("mirror_calendar_id", &self.mirror_calendar_id)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// An outbound webhook subscription.
#[derive(Clone, PartialEq)]
pub struct WebhookSubscription {
    /// Webhook id.
    pub id: WebhookId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Target URL (https only; the egress policy applies on every send).
    pub url: url::Url,
    /// Free-text description.
    pub description: Option<String>,
    /// The signing secret, sealed with the secret sealer.
    pub sealed_secret: Vec<u8>,
    /// The previous signing secret, sealed, valid during rotation.
    pub sealed_secret_previous: Option<Vec<u8>>,
    /// When the secret was last rotated.
    pub secret_rotated_at: Option<DateTime<Utc>>,
    /// The event types the subscription receives.
    pub events: Vec<EventType>,
    /// Whether payloads carry details such as summary and times.
    pub include_details: bool,
    /// Inactive subscriptions receive nothing.
    pub active: bool,
    /// Consecutive failed deliveries.
    pub failure_count: u32,
    /// Why the subscription was disabled automatically.
    pub disabled_reason: Option<String>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last modification time.
    pub updated_at: DateTime<Utc>,
    /// Optimistic concurrency counter.
    pub version: i64,
}

impl fmt::Debug for WebhookSubscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookSubscription")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("url", &self.url.as_str())
            .field("sealed_secret", &redacted(&self.sealed_secret))
            .field("events", &self.events)
            .field("include_details", &self.include_details)
            .field("active", &self.active)
            .field("failure_count", &self.failure_count)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at() -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000, 0).unwrap()
    }

    fn id<T: From<uuid::Uuid>>(n: u128) -> T {
        T::from(uuid::Uuid::from_u128(n))
    }

    #[test]
    fn enums_use_their_database_spelling() {
        assert_eq!(
            serde_json::to_string(&GrantAccess::ReadWrite).unwrap(),
            "\"read_write\""
        );
        assert_eq!(
            serde_json::to_string(&NotificationKind::InviteReply).unwrap(),
            "\"invite_reply\""
        );
        for kind in CalendarKind::ALL {
            assert_eq!(kind.as_str().parse::<CalendarKind>().unwrap(), *kind);
            assert_eq!(
                serde_json::from_str::<CalendarKind>(&format!("\"{kind}\"")).unwrap(),
                *kind
            );
        }
        assert_eq!(CalendarKind::ALL.len(), 5);
        assert_eq!(PrincipalKind::ALL.len(), 4);
        assert_eq!(GrantStatus::ALL.len(), 3);
        assert!("owner".parse::<GrantAccess>().is_err());
        assert_eq!("owner".parse::<GrantAccess>().unwrap_err().kind(), "GrantAccess");
    }

    #[test]
    fn secret_bearing_entities_do_not_debug_print_hashes() {
        let password = AppPassword {
            id: id(1),
            tenant_id: id(2),
            principal_id: id(3),
            label: "iPhone".to_owned(),
            prefix: "abcd-efgh".to_owned(),
            hash: vec![0xde, 0xad, 0xbe, 0xef],
            pepper_kid: "k1".to_owned(),
            last_used_at: None,
            revoked_at: None,
            created_at: at(),
            updated_at: at(),
            version: 1,
        };
        let shown = format!("{password:?}");
        assert!(shown.contains("abcd-efgh"));
        assert!(shown.contains("4 bytes redacted"));
        assert!(!shown.contains("222"), "{shown}");
        assert!(!shown.contains("dead"), "{shown}");

        let account = ExternalAccount {
            id: id(1),
            tenant_id: id(2),
            principal_id: id(3),
            provider: "google".to_owned(),
            account_ref: "acct".to_owned(),
            sealed_tokens: b"sealed-secret-bytes".to_vec(),
            mirror_calendar_id: None,
            sync_state: serde_json::json!({"cursor": "c"}),
            status: ExternalAccountStatus::Active,
            last_error: None,
            created_at: at(),
            updated_at: at(),
            version: 1,
        };
        let shown = format!("{account:?}");
        assert!(shown.contains("19 bytes redacted"));
        assert!(!shown.contains("115"), "{shown}");
        assert!(!shown.contains("cursor"), "{shown}");
    }

    #[test]
    fn tokens_and_webhooks_do_not_debug_print_hashes_or_secrets() {
        let token = ApiToken {
            id: id(1),
            tenant_id: Some(id(2)),
            kind: TokenKind::Tenant,
            principal_id: None,
            label: "provisioning".to_owned(),
            scopes: ScopeSet::default(),
            prefix: "dh_t_abcdefg".to_owned(),
            hash: vec![0xca, 0xfe],
            pepper_kid: "k1".to_owned(),
            expires_at: None,
            created_by: None,
            allowed_origins: Vec::new(),
            last_used_at: None,
            revoked_at: None,
            created_at: at(),
            updated_at: at(),
            version: 1,
        };
        let shown = format!("{token:?}");
        assert!(
            shown.contains("dh_t_abcdefg") && shown.contains("provisioning"),
            "{shown}"
        );
        assert!(shown.contains("2 bytes redacted"), "{shown}");
        assert!(!shown.contains("202") && !shown.contains("254"), "{shown}");

        let feed = FeedToken {
            id: id(1),
            tenant_id: id(2),
            principal_id: id(3),
            mode: FeedMode::Busy,
            calendar_ids: vec![id(4)],
            prefix: "feedprefix12".to_owned(),
            hash: vec![0xca, 0xfe, 0xba],
            pepper_kid: "k1".to_owned(),
            revoked_at: None,
            created_at: at(),
            updated_at: at(),
            version: 1,
        };
        let shown = format!("{feed:?}");
        assert!(
            shown.contains("feedprefix12") && shown.contains("3 bytes redacted"),
            "{shown}"
        );
        assert!(!shown.contains("202") && !shown.contains("186"), "{shown}");

        let webhook = WebhookSubscription {
            id: id(1),
            tenant_id: id(2),
            url: url::Url::parse("https://hooks.example.org/in").unwrap(),
            description: Some("private notes".to_owned()),
            sealed_secret: b"sealed-current".to_vec(),
            sealed_secret_previous: Some(b"sealed-previous-secret".to_vec()),
            secret_rotated_at: None,
            events: Vec::new(),
            include_details: false,
            active: true,
            failure_count: 0,
            disabled_reason: None,
            created_at: at(),
            updated_at: at(),
            version: 1,
        };
        let shown = format!("{webhook:?}");
        assert!(shown.contains("https://hooks.example.org/in"), "{shown}");
        assert!(shown.contains("14 bytes redacted"), "{shown}");
        // The previous secret is not shown at all; neither is any byte of either secret.
        assert!(!shown.contains("115, 101"), "{shown}");
        assert!(
            !shown.contains("22 bytes") && !shown.contains("private notes"),
            "{shown}"
        );
    }
}
