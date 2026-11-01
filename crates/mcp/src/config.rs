//! Configuration of the MCP server.
//!
//! The `[mcp]` table (PLAN 2.12). The server is mounted behind the HTTP edge layers; calls need a principal token
//! with `mcp:*` scopes, and the tenant must have switched MCP on (`tenant.settings.mcp_enabled`, off by default: the
//! application refuses to mint such tokens for another tenant and to authenticate them on this endpoint).
//! `allowed_origins` is the list of browser origins the `Origin` header is validated against (clients that are not
//! browsers send none). The request budgets of a token are the configuration of the rate limiter
//! (`[plugin.memory.buckets.mcp_read]` and `mcp_write`), not of this table: the limiter is a port the deployment chooses.

use davhaven_app::config::ConfigError;
use davhaven_domain::ApiLimits;
use davhaven_http::cors::is_valid_origin;
use schemars::JsonSchema;
use serde::Deserialize;

/// The `[mcp]` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct McpConfig {
    /// Whether the `/mcp` endpoint is served at all. Tenants additionally switch MCP on in their settings
    /// (`mcp_enabled`, off by default).
    pub enabled: bool,
    /// The origins an `Origin` header may carry; requests with another origin are refused.
    pub allowed_origins: Vec<String>,
    /// The longest time range (in days) `list_events`, `search_events`, `free_busy` and `find_free_slots` accept.
    pub max_range_days: u32,
    /// The most results one tool call returns (the cap of every `limit`). It must not exceed `limits.api.max_page_size`,
    /// which caps every page of the application.
    pub max_results: u32,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_origins: Vec::new(),
            max_range_days: 92,
            max_results: 200,
        }
    }
}

impl McpConfig {
    /// Checks the ranges and the origins.
    ///
    /// # Errors
    ///
    /// A [`ConfigError`] for the first unusable key of `mcp`.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !(1..=366).contains(&self.max_range_days) {
            return Err(ConfigError::new("mcp", "max_range_days", "must be between 1 and 366"));
        }
        if self.max_results == 0 {
            return Err(ConfigError::new("mcp", "max_results", "must be at least 1"));
        }
        if !self.allowed_origins.iter().all(|origin| is_valid_origin(origin)) {
            return Err(ConfigError::new(
                "mcp",
                "allowed_origins",
                "entries must be origins such as https://assistant.example.org (scheme, host, optional port)",
            ));
        }
        Ok(())
    }

    /// Checks the keys that depend on the API limits: a page of the application is never larger than
    /// `limits.api.max_page_size`, so a larger `max_results` would promise results that no call can return.
    ///
    /// # Errors
    ///
    /// A [`ConfigError`] for `max_results` when it exceeds the page size the application allows.
    pub fn validate_against(&self, api: &ApiLimits) -> Result<(), ConfigError> {
        if self.max_results > api.max_page_size {
            return Err(ConfigError::new(
                "mcp",
                "max_results",
                "must not exceed limits.api.max_page_size, which caps every page of the application",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_the_plan_values() {
        let config = McpConfig::default();
        assert!(config.enabled);
        assert_eq!((config.max_range_days, config.max_results), (92, 200));
        assert_eq!(config.allowed_origins.len(), 0);
        config.validate().unwrap();
        config.validate_against(&ApiLimits::default()).unwrap();
        let parsed: McpConfig =
            serde_json::from_str(r#"{"allowed_origins": ["https://assistant.example.org"], "max_range_days": 31}"#)
                .unwrap();
        assert_eq!(parsed.max_range_days, 31);
        parsed.validate().unwrap();
        assert!(serde_json::from_str::<McpConfig>(r#"{"max_range": 31}"#).is_err());
    }

    #[test]
    fn the_budgets_are_no_key_of_this_table() {
        // They belong to the rate limiter (`[plugin.memory.buckets.mcp_read]`), a port the deployment chooses.
        assert!(serde_json::from_str::<McpConfig>(r#"{"rate_limit": {"writes_per_minute": 5}}"#).is_err());
    }

    #[test]
    fn validation_names_the_key() {
        let cases = [
            (
                McpConfig {
                    max_range_days: 0,
                    ..McpConfig::default()
                },
                "max_range_days",
            ),
            (
                McpConfig {
                    max_range_days: 367,
                    ..McpConfig::default()
                },
                "max_range_days",
            ),
            (
                McpConfig {
                    max_results: 0,
                    ..McpConfig::default()
                },
                "max_results",
            ),
            (
                McpConfig {
                    allowed_origins: vec!["https://example.org/path".to_owned()],
                    ..McpConfig::default()
                },
                "allowed_origins",
            ),
        ];
        for (config, key) in cases {
            let error = config.validate().unwrap_err();
            assert_eq!((error.section(), error.key()), ("mcp", key));
        }
        for days in [1, 366] {
            McpConfig {
                max_range_days: days,
                ..McpConfig::default()
            }
            .validate()
            .unwrap();
        }
        McpConfig {
            max_results: 1,
            ..McpConfig::default()
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn a_result_cap_beyond_the_page_size_of_the_application_is_refused() {
        let api = ApiLimits {
            max_page_size: 50,
            default_page_size: 20,
            ..ApiLimits::default()
        };
        let too_many = McpConfig {
            max_results: 51,
            ..McpConfig::default()
        };
        let error = too_many.validate_against(&api).unwrap_err();
        assert_eq!((error.section(), error.key()), ("mcp", "max_results"));
        let fits = McpConfig {
            max_results: 50,
            ..McpConfig::default()
        };
        fits.validate_against(&api).unwrap();
    }
}
