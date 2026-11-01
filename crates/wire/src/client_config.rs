//! Client configuration responses (generic, Apple mobileconfig, DAVx5).
//!
//! `GET …/client-config/generic` returns the values a user types into a calendar client; it contains no secret.
//! The `POST` variants mint an app password for the device: the Apple profile (`application/x-apple-aspen-config`)
//! is a binary document and has no JSON type here, the DAVx5 variant returns a login URI for QR codes.

use core::fmt;

use davhaven_domain::{CredentialId, DomainName, TenantSlug};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;
use utoipa::ToSchema;

/// The values a person enters into a CalDAV client. Contains no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct ClientConfigGeneric {
    /// The tenant slug.
    #[schema(value_type = String)]
    pub tenant: TenantSlug,
    /// The login name to enter: `name@login_domain` when the tenant has a login domain, the bare name otherwise.
    pub username: String,
    /// The tenant's login domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub login_domain: Option<DomainName>,
    /// The server address for clients with automatic discovery (`/.well-known/caldav`).
    #[schema(value_type = String)]
    pub well_known_url: Url,
    /// The DAV entry point (`/dav/`) for clients that ask for a server URL.
    #[schema(value_type = String)]
    pub server_url: Url,
    /// The URL of the principal resource.
    #[schema(value_type = String)]
    pub principal_url: Url,
    /// The URL of the calendar home, for clients that need a calendar collection URL.
    #[schema(value_type = String)]
    pub calendar_home_url: Url,
}

/// The body of `POST …/client-config/{apple-mobileconfig,davx5}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientConfigRequest {
    /// The label of the app password that is minted for the device.
    pub app_password_label: String,
    /// Whether the profile also subscribes the device to the principal's feed.
    #[serde(default)]
    pub include_feed: bool,
}

/// A DAVx5 login: the URI to show as a QR code. It contains the minted app password.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct ClientConfigDavx5 {
    /// The id of the minted app password.
    #[schema(value_type = Uuid)]
    pub app_password_id: CredentialId,
    /// The login URI (contains the secret; the response is `no-store`).
    pub login_uri: String,
}

impl fmt::Debug for ClientConfigDavx5 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfigDavx5")
            .field("app_password_id", &self.app_password_id)
            .field("login_uri", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_default_to_no_feed_and_reject_unknown_members() {
        let request: ClientConfigRequest = serde_json::from_str(r#"{"app_password_label": "Phone"}"#).unwrap();
        assert!(!request.include_feed);
        assert!(serde_json::from_str::<ClientConfigRequest>(r#"{"app_password_label": "x", "feed": true}"#).is_err());
    }

    #[test]
    fn the_davx5_login_uri_is_not_debug_printed() {
        let login = ClientConfigDavx5 {
            app_password_id: CredentialId::parse("018f3c1e-7b2a-7c3d-9e4f-000000000001").unwrap(),
            login_uri: "caldavs://anna:SECRET@cal.example.org/dav/".to_owned(),
        };
        let shown = format!("{login:?}");
        assert!(!shown.contains("SECRET"), "{shown}");
        assert!(serde_json::to_string(&login).unwrap().contains("SECRET"));
    }
}
