//! API token scopes and scope sets.
//!
//! Scopes gate what a token may do on the API and MCP surfaces (PLAN 2.6). Which scopes a token may carry depends
//! on its [`TokenKind`]: system tokens only manage tenants, tenant tokens administer one tenant, and principal
//! tokens act as one principal (the only kind that can carry `mcp:*` scopes).

use core::fmt;
use core::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The kind of an API token (`api_tokens.kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TokenKind {
    /// Operates on tenants only (`system:tenants`); never reads calendar data. Not bound to a tenant.
    System,
    /// Acts as administrator of one tenant within its scopes.
    Tenant,
    /// Acts as exactly one principal, through the same authorization as DAV.
    Principal,
}

impl TokenKind {
    /// Every token kind.
    pub const ALL: [Self; 3] = [Self::System, Self::Tenant, Self::Principal];

    /// The database and JSON spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Tenant => "tenant",
            Self::Principal => "principal",
        }
    }
}

impl fmt::Display for TokenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A permission scope of an API token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub enum Scope {
    /// `system:tenants`: create, read, update and delete tenants.
    #[serde(rename = "system:tenants")]
    SystemTenants,
    /// `principals:read`: read principals, memberships and client configuration.
    #[serde(rename = "principals:read")]
    PrincipalsRead,
    /// `principals:write`: create, update and delete principals and memberships.
    #[serde(rename = "principals:write")]
    PrincipalsWrite,
    /// `credentials:write`: create and revoke app passwords, API tokens and feed tokens.
    #[serde(rename = "credentials:write")]
    CredentialsWrite,
    /// `calendars:read`: read calendars.
    #[serde(rename = "calendars:read")]
    CalendarsRead,
    /// `calendars:write`: create, update and delete calendars and grants.
    #[serde(rename = "calendars:write")]
    CalendarsWrite,
    /// `events:read`: read calendar objects.
    #[serde(rename = "events:read")]
    EventsRead,
    /// `events:write`: create, update and delete calendar objects.
    #[serde(rename = "events:write")]
    EventsWrite,
    /// `webhooks:manage`: manage webhook subscriptions and deliveries.
    #[serde(rename = "webhooks:manage")]
    WebhooksManage,
    /// `providers:manage`: manage external provider accounts.
    #[serde(rename = "providers:manage")]
    ProvidersManage,
    /// `outbox:manage`: inspect and retry dead outbox messages.
    #[serde(rename = "outbox:manage")]
    OutboxManage,
    /// `audit:read`: read audit events.
    #[serde(rename = "audit:read")]
    AuditRead,
    /// `itip:inbound`: deliver inbound iTIP messages from a mail gateway.
    #[serde(rename = "itip:inbound")]
    ItipInbound,
    /// `mcp:read`: read-only MCP tools.
    #[serde(rename = "mcp:read")]
    McpRead,
    /// `mcp:write`: MCP tools that change calendars.
    #[serde(rename = "mcp:write")]
    McpWrite,
    /// `mcp:schedule_external`: MCP writes that invite external attendees.
    #[serde(rename = "mcp:schedule_external")]
    McpScheduleExternal,
}

/// Error returned for text that is not a known scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unknown scope")]
pub struct UnknownScope;

impl Scope {
    /// Every scope, in catalog order.
    pub const ALL: [Self; 16] = [
        Self::SystemTenants,
        Self::PrincipalsRead,
        Self::PrincipalsWrite,
        Self::CredentialsWrite,
        Self::CalendarsRead,
        Self::CalendarsWrite,
        Self::EventsRead,
        Self::EventsWrite,
        Self::WebhooksManage,
        Self::ProvidersManage,
        Self::OutboxManage,
        Self::AuditRead,
        Self::ItipInbound,
        Self::McpRead,
        Self::McpWrite,
        Self::McpScheduleExternal,
    ];

    /// The wire spelling, for example `events:read`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SystemTenants => "system:tenants",
            Self::PrincipalsRead => "principals:read",
            Self::PrincipalsWrite => "principals:write",
            Self::CredentialsWrite => "credentials:write",
            Self::CalendarsRead => "calendars:read",
            Self::CalendarsWrite => "calendars:write",
            Self::EventsRead => "events:read",
            Self::EventsWrite => "events:write",
            Self::WebhooksManage => "webhooks:manage",
            Self::ProvidersManage => "providers:manage",
            Self::OutboxManage => "outbox:manage",
            Self::AuditRead => "audit:read",
            Self::ItipInbound => "itip:inbound",
            Self::McpRead => "mcp:read",
            Self::McpWrite => "mcp:write",
            Self::McpScheduleExternal => "mcp:schedule_external",
        }
    }

    /// Bit position inside a [`ScopeSet`].
    const fn bit(self) -> u32 {
        let index: u32 = match self {
            Self::SystemTenants => 0,
            Self::PrincipalsRead => 1,
            Self::PrincipalsWrite => 2,
            Self::CredentialsWrite => 3,
            Self::CalendarsRead => 4,
            Self::CalendarsWrite => 5,
            Self::EventsRead => 6,
            Self::EventsWrite => 7,
            Self::WebhooksManage => 8,
            Self::ProvidersManage => 9,
            Self::OutboxManage => 10,
            Self::AuditRead => 11,
            Self::ItipInbound => 12,
            Self::McpRead => 13,
            Self::McpWrite => 14,
            Self::McpScheduleExternal => 15,
        };
        1 << index
    }

    /// Whether a token of `kind` may carry this scope.
    ///
    /// System tokens carry only `system:tenants`. Tenant tokens carry every administrative scope except
    /// `system:tenants` and the `mcp:*` scopes. Principal tokens carry the calendar, event and `mcp:*` scopes.
    pub const fn allowed_for(self, kind: TokenKind) -> bool {
        match kind {
            TokenKind::System => matches!(self, Self::SystemTenants),
            TokenKind::Tenant => !matches!(
                self,
                Self::SystemTenants | Self::McpRead | Self::McpWrite | Self::McpScheduleExternal
            ),
            TokenKind::Principal => matches!(
                self,
                Self::CalendarsRead
                    | Self::CalendarsWrite
                    | Self::EventsRead
                    | Self::EventsWrite
                    | Self::McpRead
                    | Self::McpWrite
                    | Self::McpScheduleExternal
            ),
        }
    }

    /// Whether a token carrying this scope must expire (`mcp:*` scopes require a principal token with
    /// `expires_at`, at most `security.max_mcp_token_days` away).
    pub const fn requires_expiry(self) -> bool {
        matches!(self, Self::McpRead | Self::McpWrite | Self::McpScheduleExternal)
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Scope {
    type Err = UnknownScope;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|scope| scope.as_str() == input)
            .ok_or(UnknownScope)
    }
}

/// A set of scopes. Serialized as a sorted JSON array of scope strings; duplicates collapse on input.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(from = "Vec<Scope>", into = "Vec<Scope>")]
#[schemars(with = "Vec<Scope>")]
pub struct ScopeSet(u32);

impl ScopeSet {
    /// The empty set.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Every scope.
    pub fn all() -> Self {
        Self::ALL_BITS
    }

    const ALL_BITS: Self = Self((1 << 16) - 1);

    /// Builds a set from a slice of scopes.
    pub fn of(scopes: &[Scope]) -> Self {
        scopes.iter().copied().collect()
    }

    /// Whether the set contains `scope`.
    pub const fn contains(self, scope: Scope) -> bool {
        self.0 & scope.bit() != 0
    }

    /// Adds `scope`.
    pub fn insert(&mut self, scope: Scope) {
        self.0 |= scope.bit();
    }

    /// Returns the set with `scope` added.
    #[must_use]
    pub const fn with(self, scope: Scope) -> Self {
        Self(self.0 | scope.bit())
    }

    /// The union of two sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// The scopes present in both sets.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Whether every scope of `self` is also in `other` (a token may only mint tokens whose scopes are a subset
    /// of its own).
    pub const fn is_subset_of(self, other: Self) -> bool {
        self.0 & !other.0 == 0
    }

    /// Whether the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The number of scopes in the set.
    pub const fn len(self) -> u32 {
        self.0.count_ones()
    }

    /// The scopes in catalog order.
    pub fn iter(self) -> impl Iterator<Item = Scope> {
        Scope::ALL.into_iter().filter(move |scope| self.contains(*scope))
    }

    /// The first scope in the set that a token of `kind` may not carry, if any.
    pub fn first_not_allowed_for(self, kind: TokenKind) -> Option<Scope> {
        self.iter().find(|scope| !scope.allowed_for(kind))
    }

    /// The wire spellings in catalog order (the `scopes text[]` column).
    pub fn to_strings(self) -> Vec<&'static str> {
        self.iter().map(Scope::as_str).collect()
    }

    /// Parses wire spellings.
    ///
    /// # Errors
    ///
    /// Returns [`UnknownScope`] when any entry is not a known scope.
    pub fn parse_all<'a>(items: impl IntoIterator<Item = &'a str>) -> Result<Self, UnknownScope> {
        items.into_iter().map(str::parse::<Scope>).collect()
    }
}

impl fmt::Debug for ScopeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter().map(Scope::as_str)).finish()
    }
}

impl FromIterator<Scope> for ScopeSet {
    fn from_iter<T: IntoIterator<Item = Scope>>(iter: T) -> Self {
        let mut set = Self::empty();
        for scope in iter {
            set.insert(scope);
        }
        set
    }
}

impl<'a> FromIterator<&'a Scope> for ScopeSet {
    fn from_iter<T: IntoIterator<Item = &'a Scope>>(iter: T) -> Self {
        iter.into_iter().copied().collect()
    }
}

impl Extend<Scope> for ScopeSet {
    fn extend<T: IntoIterator<Item = Scope>>(&mut self, iter: T) {
        for scope in iter {
            self.insert(scope);
        }
    }
}

impl From<Vec<Scope>> for ScopeSet {
    fn from(scopes: Vec<Scope>) -> Self {
        scopes.into_iter().collect()
    }
}

impl From<ScopeSet> for Vec<Scope> {
    fn from(set: ScopeSet) -> Self {
        set.iter().collect()
    }
}

impl<const N: usize> From<[Scope; N]> for ScopeSet {
    fn from(scopes: [Scope; N]) -> Self {
        scopes.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spellings_round_trip() {
        for scope in Scope::ALL {
            assert_eq!(scope.as_str().parse::<Scope>().unwrap(), scope);
            assert_eq!(
                serde_json::to_string(&scope).unwrap(),
                format!("\"{}\"", scope.as_str())
            );
            assert_eq!(serde_json::from_str::<Scope>(&format!("\"{scope}\"")).unwrap(), scope);
        }
        assert_eq!(Scope::ALL.len(), 16);
        assert!("events".parse::<Scope>().is_err());
        assert!("Events:Read".parse::<Scope>().is_err());
        assert!("".parse::<Scope>().is_err());
    }

    #[test]
    fn catalog_has_unique_bits_and_names() {
        let mut bits = 0u32;
        let mut names = std::collections::BTreeSet::new();
        for scope in Scope::ALL {
            assert_eq!(bits & scope.bit(), 0, "{scope} reuses a bit");
            bits |= scope.bit();
            assert!(names.insert(scope.as_str()));
        }
        assert_eq!(ScopeSet(bits), ScopeSet::all());
    }

    #[test]
    fn token_kinds_carry_only_their_scopes() {
        let system: Vec<_> = Scope::ALL
            .into_iter()
            .filter(|s| s.allowed_for(TokenKind::System))
            .collect();
        assert_eq!(system, vec![Scope::SystemTenants]);

        let tenant: Vec<_> = Scope::ALL
            .into_iter()
            .filter(|s| s.allowed_for(TokenKind::Tenant))
            .collect();
        assert_eq!(
            tenant,
            vec![
                Scope::PrincipalsRead,
                Scope::PrincipalsWrite,
                Scope::CredentialsWrite,
                Scope::CalendarsRead,
                Scope::CalendarsWrite,
                Scope::EventsRead,
                Scope::EventsWrite,
                Scope::WebhooksManage,
                Scope::ProvidersManage,
                Scope::OutboxManage,
                Scope::AuditRead,
                Scope::ItipInbound,
            ]
        );

        let principal: Vec<_> = Scope::ALL
            .into_iter()
            .filter(|s| s.allowed_for(TokenKind::Principal))
            .collect();
        assert_eq!(
            principal,
            vec![
                Scope::CalendarsRead,
                Scope::CalendarsWrite,
                Scope::EventsRead,
                Scope::EventsWrite,
                Scope::McpRead,
                Scope::McpWrite,
                Scope::McpScheduleExternal,
            ]
        );
    }

    #[test]
    fn only_mcp_scopes_require_expiry() {
        for scope in Scope::ALL {
            assert_eq!(scope.requires_expiry(), scope.as_str().starts_with("mcp:"), "{scope}");
        }
    }

    #[test]
    fn set_operations() {
        let read = ScopeSet::of(&[Scope::EventsRead, Scope::CalendarsRead]);
        let write = read.with(Scope::EventsWrite);
        assert!(read.contains(Scope::EventsRead));
        assert!(!read.contains(Scope::EventsWrite));
        assert!(read.is_subset_of(write));
        assert!(!write.is_subset_of(read));
        assert!(ScopeSet::empty().is_subset_of(read));
        assert!(read.is_subset_of(read));
        assert_eq!(read.union(write), write);
        assert_eq!(write.intersection(read), read);
        assert_eq!(write.len(), 3);
        assert!(!write.is_empty());
        assert!(ScopeSet::empty().is_empty());
        assert_eq!(ScopeSet::all().len(), 16);
        assert_eq!(ScopeSet::default(), ScopeSet::empty());
        let mut grown = ScopeSet::empty();
        grown.extend([Scope::AuditRead]);
        assert_eq!(grown, ScopeSet::from([Scope::AuditRead]));
    }

    #[test]
    fn kind_validation_names_the_offending_scope() {
        let mixed = ScopeSet::of(&[Scope::EventsRead, Scope::McpRead, Scope::SystemTenants]);
        assert_eq!(
            mixed.first_not_allowed_for(TokenKind::Tenant),
            Some(Scope::SystemTenants)
        );
        assert_eq!(
            mixed.first_not_allowed_for(TokenKind::Principal),
            Some(Scope::SystemTenants)
        );
        assert_eq!(mixed.first_not_allowed_for(TokenKind::System), Some(Scope::EventsRead));
        assert_eq!(
            ScopeSet::of(&[Scope::EventsRead]).first_not_allowed_for(TokenKind::Principal),
            None
        );
        assert_eq!(ScopeSet::empty().first_not_allowed_for(TokenKind::System), None);
    }

    #[test]
    fn serde_is_a_sorted_deduplicated_array() {
        let set: ScopeSet = serde_json::from_str(r#"["events:write","calendars:read","events:write"]"#).unwrap();
        assert_eq!(
            serde_json::to_string(&set).unwrap(),
            r#"["calendars:read","events:write"]"#
        );
        assert!(serde_json::from_str::<ScopeSet>(r#"["events:write","bogus"]"#).is_err());
        assert!(serde_json::from_str::<ScopeSet>(r#""events:write""#).is_err());
        assert_eq!(set.to_strings(), vec!["calendars:read", "events:write"]);
        assert_eq!(ScopeSet::parse_all(["audit:read", "outbox:manage"]).unwrap().len(), 2);
        assert!(ScopeSet::parse_all(["audit:read", "nope"]).is_err());
        assert_eq!(format!("{set:?}"), r#"{"calendars:read", "events:write"}"#);
    }

    #[test]
    fn token_kind_spelling() {
        for kind in TokenKind::ALL {
            assert_eq!(serde_json::to_string(&kind).unwrap(), format!("\"{}\"", kind.as_str()));
            assert_eq!(kind.to_string(), kind.as_str());
        }
    }
}
