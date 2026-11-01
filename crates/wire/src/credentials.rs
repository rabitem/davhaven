//! Credential creation responses (app passwords, API tokens, feed tokens).
//!
//! Server-generated secrets are shown exactly once, in the response that creates them (PLAN 2.6). The `*Created`
//! types carry the plaintext; they implement `Debug` by hand and never print it, and responses containing them are
//! sent with `Cache-Control: no-store` and are never stored for idempotent replay. The `*View` types are what
//! listings show afterwards: ids, labels, prefixes and state, never a secret or a hash.

use core::fmt;

use chrono::{DateTime, Utc};
use davhaven_domain::{CalendarId, CredentialId, FeedMode, PrincipalId, PrincipalName, ScopeSet, TokenId, TokenKind};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;
use utoipa::ToSchema;

/// An app password as listings show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct AppPasswordView {
    /// The credential id.
    #[schema(value_type = Uuid)]
    pub id: CredentialId,
    /// The label chosen at creation, usually the device name.
    pub label: String,
    /// The first two groups of the password, which identify it (for example `abcd-efgh`).
    pub prefix: String,
    /// When the password was last used, with a granularity of 15 minutes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
    /// When the password was revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    /// When the password was created.
    pub created_at: DateTime<Utc>,
}

/// The body of `POST …/app-passwords`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AppPasswordCreate {
    /// A label for the password, usually the device name (1 to 100 characters).
    pub label: String,
}

/// A freshly created app password. The plaintext is shown only here.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct AppPasswordCreated {
    /// The credential id.
    #[schema(value_type = Uuid)]
    pub id: CredentialId,
    /// The label.
    pub label: String,
    /// The first two groups of the password.
    pub prefix: String,
    /// The password: nine groups of four lowercase base32 characters separated by hyphens.
    pub password: String,
    /// When the password was created.
    pub created_at: DateTime<Utc>,
}

impl fmt::Debug for AppPasswordCreated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppPasswordCreated")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("prefix", &self.prefix)
            .field("password", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// An API token as listings show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct ApiTokenView {
    /// The token id.
    #[schema(value_type = Uuid)]
    pub id: TokenId,
    /// Whether the token administers the tenant (`tenant`) or acts as one principal (`principal`).
    #[schema(schema_with = crate::schema::token_kind)]
    pub kind: TokenKind,
    /// The id of the principal a principal token acts as.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Uuid>)]
    pub principal_id: Option<PrincipalId>,
    /// The name of the principal a principal token acts as.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub principal: Option<PrincipalName>,
    /// The label chosen at creation.
    pub label: String,
    /// The scopes the token carries.
    #[schema(value_type = Vec<String>)]
    pub scopes: ScopeSet,
    /// The 12 character prefix of the token (`dvh_pat_{prefix}_…`).
    pub prefix: String,
    /// When the token expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// The origins that may call the API with this token from a browser.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_origins: Vec<String>,
    /// The token that minted this one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Uuid>)]
    pub created_by: Option<TokenId>,
    /// When the token was last used, with a granularity of 15 minutes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
    /// When the token was revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    /// When the token was created.
    pub created_at: DateTime<Utc>,
}

/// The body of `POST …/api-tokens`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ApiTokenCreate {
    /// `tenant` for an administration token, `principal` for a token that acts as one principal.
    #[schema(schema_with = crate::schema::token_kind)]
    pub kind: TokenKind,
    /// The principal a `principal` token acts as: any principal except a group (a user, a service principal or a
    /// resource); required for that kind, forbidden for the others. The token acts **as** this principal, through the same decisions as DAV.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub principal: Option<PrincipalName>,
    /// A label for the token (1 to 100 characters).
    pub label: String,
    /// The scopes, allowed for the kind: a subset of the scopes of the token that creates this one, **except** that a
    /// principal token for a **service principal** may carry the `mcp:*` scopes, which a tenant token cannot hold
    /// itself (`credentials:write` is already the power to act as a principal).
    #[schema(value_type = Vec<String>)]
    pub scopes: ScopeSet,
    /// When the token expires; required for tokens with `mcp:*` scopes, which also have a maximum lifetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// The origins that may call the API with this token from a browser.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_origins: Vec<String>,
}

/// A freshly created API token. The plaintext is shown only here.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct ApiTokenCreated {
    /// The token as it will be listed afterwards.
    pub token: ApiTokenView,
    /// The secret in the format `dvh_pat_{prefix}_{secret}`; present it as a `Bearer` token.
    pub secret: String,
}

impl fmt::Debug for ApiTokenCreated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiTokenCreated")
            .field("token", &self.token)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// A feed token as listings show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct FeedTokenView {
    /// The token id.
    #[schema(value_type = Uuid)]
    pub id: TokenId,
    /// Full details or busy time only.
    #[schema(schema_with = crate::schema::feed_mode)]
    pub mode: FeedMode,
    /// The calendars the feed contains.
    #[schema(value_type = Vec<Uuid>)]
    pub calendar_ids: Vec<CalendarId>,
    /// The 12 character prefix of the token.
    pub prefix: String,
    /// When the token was revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    /// When the token was created.
    pub created_at: DateTime<Utc>,
}

/// The body of `POST …/feed-tokens`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedTokenCreate {
    /// Full details or busy time only.
    #[schema(schema_with = crate::schema::feed_mode)]
    pub mode: FeedMode,
    /// The calendars the feed contains; the principal must have read access to each of them.
    #[schema(value_type = Vec<Uuid>)]
    pub calendar_ids: Vec<CalendarId>,
}

/// A freshly created (or rotated) feed token. The URL contains the secret and is shown only here.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct FeedTokenCreated {
    /// The token as it will be listed afterwards.
    pub token: FeedTokenView,
    /// The subscription URL: `/feeds/{secret}.ics` on the public base URL.
    #[schema(value_type = String)]
    pub feed_url: Url,
}

impl fmt::Debug for FeedTokenCreated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FeedTokenCreated")
            .field("token", &self.token)
            .field("feed_url", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use davhaven_domain::Scope;

    use super::*;

    #[test]
    fn created_secrets_never_appear_in_debug_output() {
        let created = AppPasswordCreated {
            id: CredentialId::parse("018f3c1e-7b2a-7c3d-9e4f-000000000001").unwrap(),
            label: "iPhone".to_owned(),
            prefix: "abcd-efgh".to_owned(),
            password: "abcd-efgh-ijkl-mnop-qrst-uvwx-2345".to_owned(),
            created_at: DateTime::UNIX_EPOCH,
        };
        let shown = format!("{created:?}");
        assert!(shown.contains("redacted") && !shown.contains("ijkl"), "{shown}");

        let token = ApiTokenCreated {
            token: ApiTokenView {
                id: TokenId::parse("018f3c1e-7b2a-7c3d-9e4f-000000000002").unwrap(),
                kind: TokenKind::Tenant,
                principal_id: None,
                principal: None,
                label: "provisioning".to_owned(),
                scopes: ScopeSet::of(&[Scope::PrincipalsRead]),
                prefix: "abcdefghijkl".to_owned(),
                expires_at: None,
                allowed_origins: Vec::new(),
                created_by: None,
                last_used_at: None,
                revoked_at: None,
                created_at: DateTime::UNIX_EPOCH,
            },
            secret: "dvh_pat_abcdefghijkl_SECRETSECRETSECRET".to_owned(),
        };
        let shown = format!("{token:?}");
        assert!(shown.contains("redacted") && !shown.contains("SECRET"), "{shown}");
        let json = serde_json::to_value(&token).unwrap();
        assert_eq!(json["secret"], "dvh_pat_abcdefghijkl_SECRETSECRETSECRET");
        assert_eq!(json["token"]["scopes"], serde_json::json!(["principals:read"]));

        let feed = FeedTokenCreated {
            token: FeedTokenView {
                id: TokenId::parse("018f3c1e-7b2a-7c3d-9e4f-000000000003").unwrap(),
                mode: FeedMode::Busy,
                calendar_ids: Vec::new(),
                prefix: "abcdefghijkl".to_owned(),
                revoked_at: None,
                created_at: DateTime::UNIX_EPOCH,
            },
            feed_url: Url::parse("https://cal.example.org/feeds/dvh_feed_abc_SECRET.ics").unwrap(),
        };
        let shown = format!("{feed:?}");
        assert!(shown.contains("redacted") && !shown.contains("SECRET"), "{shown}");
    }

    #[test]
    fn creation_requests_reject_unknown_members() {
        assert!(serde_json::from_str::<AppPasswordCreate>(r#"{"label": "Laptop"}"#).is_ok());
        assert!(serde_json::from_str::<AppPasswordCreate>(r#"{"label": "Laptop", "password": "x"}"#).is_err());
        let request: ApiTokenCreate = serde_json::from_str(
            r#"{"kind": "principal", "principal": "anna", "label": "assistant", "scopes": ["mcp:read", "events:read"]}"#,
        )
        .unwrap();
        assert_eq!(request.kind, TokenKind::Principal);
        assert!(request.scopes.contains(Scope::McpRead));
        assert!(
            serde_json::from_str::<ApiTokenCreate>(r#"{"kind": "tenant", "label": "x", "scopes": ["nope"]}"#).is_err()
        );
    }
}
