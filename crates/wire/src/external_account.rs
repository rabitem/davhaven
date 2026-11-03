//! External provider account views.
//!
//! A principal can connect an account at an external calendar provider (Google, Microsoft). Davhaven pulls its
//! events into a read-only mirror calendar (PLAN 1.1: pull only). The OAuth tokens are sealed in the store and are
//! never part of any view.

use chrono::{DateTime, Utc};
use davhaven_domain::{CalendarId, ExternalAccountId, ExternalAccountStatus, PrincipalId, PrincipalName};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;
use utoipa::ToSchema;

/// A provider the deployment offers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct ProviderView {
    /// The provider name used in paths and in `POST …/external-accounts`, for example `google`.
    pub name: String,
    /// Whether the provider is enabled in this deployment; a disabled provider answers 409 `feature-not-enabled`.
    pub enabled: bool,
}

/// A connected external account as the management API shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct ExternalAccountView {
    /// The external account id.
    #[schema(value_type = Uuid)]
    pub id: ExternalAccountId,
    /// The id of the principal who connected the account.
    #[schema(value_type = Uuid)]
    pub principal_id: PrincipalId,
    /// The name of the principal who connected the account.
    #[schema(value_type = String)]
    pub principal: PrincipalName,
    /// The provider name.
    pub provider: String,
    /// The provider's reference for the account (for example the account's e-mail address).
    pub account_ref: String,
    /// The mirror calendar the events are imported into.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Uuid>)]
    pub mirror_calendar_id: Option<CalendarId>,
    /// Whether the account syncs, failed or is disabled.
    #[schema(schema_with = crate::schema::external_account_status)]
    pub status: ExternalAccountStatus,
    /// The last sync error, for operators.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Stable reason of `last_error`, when known. Accept future codes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_code: Option<String>,
    /// Last successful pull since connection; absent if unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sync_at: Option<DateTime<Utc>>,
    /// Recorded next due time, subject to availability and leases; absent if unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_sync_at: Option<DateTime<Utc>>,
    /// When the account was connected.
    pub created_at: DateTime<Utc>,
    /// When the account was last changed.
    pub updated_at: DateTime<Utc>,
}

/// The body of `POST …/external-accounts`: starts the OAuth flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ExternalAccountCreate {
    /// The provider name, as listed by `GET …/providers`.
    pub provider: String,
    /// The principal who connects the account.
    #[schema(value_type = String)]
    pub principal: PrincipalName,
}

/// The answer of `POST …/external-accounts`: where to send the person for consent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct AuthorizationUrl {
    /// The provider's consent URL, including the single-use `state` (valid for 10 minutes) and the PKCE challenge.
    #[schema(value_type = String)]
    pub authorization_url: Url,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creation_names_provider_and_principal() {
        let create: ExternalAccountCreate =
            serde_json::from_str(r#"{"provider": "google", "principal": "anna"}"#).unwrap();
        assert_eq!(create.provider, "google");
        assert_eq!(create.principal.as_str(), "anna");
        assert!(serde_json::from_str::<ExternalAccountCreate>(r#"{"provider": "google"}"#).is_err());
    }

    #[test]
    fn views_never_contain_tokens() {
        let view = ExternalAccountView {
            id: ExternalAccountId::parse("018f3c1e-7b2a-7c3d-9e4f-000000000001").unwrap(),
            principal_id: PrincipalId::parse("018f3c1e-7b2a-7c3d-9e4f-000000000002").unwrap(),
            principal: PrincipalName::parse("anna").unwrap(),
            provider: "google".to_owned(),
            account_ref: "anna@example.org".to_owned(),
            mirror_calendar_id: None,
            status: ExternalAccountStatus::Active,
            last_error: None,
            last_error_code: None,
            last_sync_at: None,
            next_sync_at: None,
            created_at: DateTime::UNIX_EPOCH,
            updated_at: DateTime::UNIX_EPOCH,
        };
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("token"), "{json}");
        assert_eq!(serde_json::from_str::<ExternalAccountView>(&json).unwrap(), view);
    }

    #[test]
    fn sync_metadata_is_optional_for_existing_clients_and_accounts() {
        let legacy = serde_json::json!({
            "id": "018f3c1e-7b2a-7c3d-9e4f-000000000001",
            "principal_id": "018f3c1e-7b2a-7c3d-9e4f-000000000002",
            "principal": "anna",
            "provider": "fake",
            "account_ref": "anna@example.org",
            "status": "active",
            "created_at": "1970-01-01T00:00:00Z",
            "updated_at": "1970-01-01T00:00:00Z",
        });
        let view: ExternalAccountView = serde_json::from_value(legacy.clone()).unwrap();
        assert_eq!(view.last_sync_at, None);
        assert_eq!(view.next_sync_at, None);
        assert_eq!(view.last_error_code, None);
        assert_eq!(
            serde_json::to_value(&view).unwrap(),
            legacy,
            "unset metadata stays absent"
        );

        let mut current = legacy;
        current["last_sync_at"] = serde_json::json!("2027-01-05T09:45:00Z");
        current["next_sync_at"] = serde_json::json!("2027-01-05T10:00:00Z");
        // The vocabulary is open so future server reasons remain readable by an older client.
        current["last_error_code"] = serde_json::json!("future_reason");
        let view: ExternalAccountView = serde_json::from_value(current.clone()).unwrap();
        assert_eq!(view.last_error_code.as_deref(), Some("future_reason"));
        assert_eq!(serde_json::to_value(view).unwrap(), current);
    }
}
