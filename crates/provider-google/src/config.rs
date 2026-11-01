//! Configuration of the provider.
//!
//! The `[providers.google]` table. The provider is compiled in only with the cargo feature `provider-google` and
//! is disabled by default: a disabled provider answers 409 `feature-not-enabled` on the API and runs no workers.
//! The client secret comes from a file, never inline.

use std::path::PathBuf;

use davhaven_ports::{PluginError, read_secret_file};
use schemars::JsonSchema;
use secrecy::SecretString;
use serde::Deserialize;
use url::Url;

/// The name of the provider, used in URLs (`/oauth/google/callback`) and in `external_accounts.provider`.
pub const PLUGIN: &str = "google";

/// The longest window, in days, either side of today that a mirror may cover (ten years).
pub const MAX_WINDOW_DAYS: u32 = 3650;

/// The `[providers.google]` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct GoogleConfig {
    /// Whether the provider is available. Off by default.
    pub enabled: bool,
    /// The OAuth client id of the Google Cloud project.
    pub client_id: Option<String>,
    /// A file with the OAuth client secret.
    pub client_secret_file: Option<PathBuf>,
    /// The redirect URI registered with the OAuth client; it must be `{public base URL}/oauth/google/callback`.
    pub redirect_uri: Option<Url>,
    /// How many days of the past the mirror covers: events that ended earlier are not imported.
    pub history_days: u32,
    /// How many days of the future the mirror covers: events that start later are not imported. A recurring series is
    /// imported whole whenever it overlaps the window.
    pub future_days: u32,
}

impl Default for GoogleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            client_id: None,
            client_secret_file: None,
            redirect_uri: None,
            history_days: 90,
            future_days: 365,
        }
    }
}

impl GoogleConfig {
    /// Checks the window, and that an enabled provider is configured completely.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] naming the missing or invalid key.
    pub fn validate(&self) -> Result<(), PluginError> {
        let invalid = |message: &str| PluginError::invalid_config(PLUGIN, message);
        for (key, days) in [("history_days", self.history_days), ("future_days", self.future_days)] {
            if days > MAX_WINDOW_DAYS {
                return Err(invalid(&format!("`{key}` must not exceed {MAX_WINDOW_DAYS} days")));
            }
        }
        if !self.enabled {
            return Ok(());
        }
        if self.client_id.as_deref().is_none_or(|id| id.trim().is_empty()) {
            return Err(invalid("`client_id` is required when the provider is enabled"));
        }
        if self.client_secret_file.is_none() {
            return Err(invalid("`client_secret_file` is required when the provider is enabled"));
        }
        let Some(redirect) = &self.redirect_uri else {
            return Err(invalid("`redirect_uri` is required when the provider is enabled"));
        };
        if !matches!(redirect.scheme(), "https" | "http") || redirect.host_str().is_none() {
            return Err(invalid("`redirect_uri` must be an http(s) URL"));
        }
        Ok(())
    }

    /// The client secret, read from `client_secret_file`.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] when the file is not set or cannot be read.
    pub fn client_secret(&self) -> Result<SecretString, PluginError> {
        let path = self
            .client_secret_file
            .as_deref()
            .ok_or_else(|| PluginError::invalid_config(PLUGIN, "`client_secret_file` is required"))?;
        read_secret_file(PLUGIN, "client_secret_file", path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(value: serde_json::Value) -> GoogleConfig {
        davhaven_ports::parse_config(PLUGIN, value).unwrap()
    }

    #[test]
    fn the_provider_is_disabled_by_default() {
        let config = parse(serde_json::json!({}));
        assert!(!config.enabled);
        config.validate().unwrap();
        assert_eq!(config, GoogleConfig::default());
        assert_eq!((config.history_days, config.future_days), (90, 365));
    }

    #[test]
    fn an_enabled_provider_needs_its_credentials() {
        let complete = parse(serde_json::json!({
            "enabled": true,
            "client_id": "1234.apps.googleusercontent.com",
            "client_secret_file": "/run/secrets/google",
            "redirect_uri": "https://cal.example.org/oauth/google/callback",
        }));
        complete.validate().unwrap();
        for (value, key) in [
            (serde_json::json!({"enabled": true}), "client_id"),
            (serde_json::json!({"enabled": true, "client_id": " "}), "client_id"),
            (
                serde_json::json!({"enabled": true, "client_id": "x"}),
                "client_secret_file",
            ),
            (
                serde_json::json!({"enabled": true, "client_id": "x", "client_secret_file": "/s"}),
                "redirect_uri",
            ),
            (
                serde_json::json!({"enabled": true, "client_id": "x", "client_secret_file": "/s", "redirect_uri": "ftp://x/cb"}),
                "redirect_uri",
            ),
        ] {
            let error = parse(value).validate().unwrap_err().to_string();
            assert!(error.contains(key), "{key}: {error}");
        }
        assert!(
            davhaven_ports::parse_config::<GoogleConfig>(PLUGIN, serde_json::json!({"client_secret": "inline"}))
                .is_err()
        );
    }

    #[test]
    fn the_window_is_bounded_even_while_the_provider_is_off() {
        parse(serde_json::json!({"history_days": 0, "future_days": 3650}))
            .validate()
            .unwrap();
        for key in ["history_days", "future_days"] {
            let error = parse(serde_json::json!({ key: 3651 }))
                .validate()
                .unwrap_err()
                .to_string();
            assert!(error.contains(key) && error.contains("3650"), "{error}");
        }
    }
}
