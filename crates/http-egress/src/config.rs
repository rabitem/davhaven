//! Configuration of the egress policy and timeouts.
//!
//! The `[security.egress]` table. By default only `https` is allowed and every private, loopback, link-local and
//! metadata address is denied after DNS resolution; redirects are never followed. A deployment that must reach an
//! internal service (for example a webhook receiver in its own network) allows it narrowly with `allow_cidrs` or
//! `allow_hosts`; `deny_cidrs` adds ranges to the built-in denials.
//!
//! Size caps and the total timeout depend on what the request is for ([`HttpPurpose`](davhaven_ports::HttpPurpose)):
//! the answer of a webhook receiver is read for its status only, an OAuth answer is a small token document, and a
//! page of events from a provider's API is large.

use std::time::Duration;

use davhaven_ports::PluginError;
use ipnet::IpNet;
use schemars::JsonSchema;
use serde::Deserialize;

/// The name of the plugin.
pub const PLUGIN: &str = "egress";

/// The `[security.egress]` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct EgressConfig {
    /// Allows plain `http` URLs. Off by default; only for tests and closed networks.
    pub allow_http: bool,
    /// Address ranges that are allowed although they are private, loopback or link-local (for example
    /// `10.20.0.0/16`). The cloud metadata address stays denied.
    #[schemars(with = "Vec<String>")]
    pub allow_cidrs: Vec<IpNet>,
    /// Host names whose resolved addresses are allowed in the same way (exact, lowercase, no wildcards).
    pub allow_hosts: Vec<String>,
    /// Further address ranges that are denied.
    #[schemars(with = "Vec<String>")]
    pub deny_cidrs: Vec<IpNet>,
    /// The ports a target may have (the port of the URL, or 443 and 80 when it names none). Empty allows every
    /// port; a deployment whose receivers all listen on 443 lists `[443]`, which keeps a tenant administrator
    /// from probing the other services of a public host.
    pub allowed_ports: Vec<u16>,
    /// The most host name lookups that run at the same time. A lookup occupies a thread of the blocking pool until
    /// the resolver answers, however long that takes, so names that never answer must not be able to starve
    /// everything else that uses the pool.
    pub max_concurrent_lookups: u32,
    /// The timeout of connecting.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub connect_timeout: Duration,
    /// The timeout of the whole request including the response body (webhooks and OAuth).
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub total_timeout: Duration,
    /// The most response bytes of a webhook delivery the client reads. The status is what counts for a webhook,
    /// so a longer answer is cut at this size and the delivery is still judged by its status.
    pub max_response_bytes: u64,
    /// The most response bytes of an OAuth call (token exchange, refresh, revocation); a larger answer fails.
    pub oauth_max_response_bytes: u64,
    /// The most response bytes of a call to a provider's calendar API (a page of events); a larger answer fails.
    pub provider_api_max_response_bytes: u64,
    /// The timeout of the whole request of a call to a provider's calendar API.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "String")]
    pub provider_api_total_timeout: Duration,
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            allow_http: false,
            allow_cidrs: Vec::new(),
            allow_hosts: Vec::new(),
            deny_cidrs: Vec::new(),
            allowed_ports: Vec::new(),
            max_concurrent_lookups: 16,
            connect_timeout: Duration::from_secs(5),
            total_timeout: Duration::from_secs(10),
            max_response_bytes: 65_536,
            oauth_max_response_bytes: 262_144,
            provider_api_max_response_bytes: 8 * 1024 * 1024,
            provider_api_total_timeout: Duration::from_secs(30),
        }
    }
}

impl EgressConfig {
    /// Checks the timeouts, the response cap and the host list.
    ///
    /// # Errors
    ///
    /// [`PluginError::InvalidConfig`] naming the offending key.
    pub fn validate(&self) -> Result<(), PluginError> {
        let invalid = |message: String| PluginError::invalid_config(PLUGIN, message);
        if self.connect_timeout.is_zero() {
            return Err(invalid("`connect_timeout` must be greater than zero".to_owned()));
        }
        if self.total_timeout < self.connect_timeout {
            return Err(invalid(
                "`total_timeout` must not be shorter than `connect_timeout`".to_owned(),
            ));
        }
        if self.provider_api_total_timeout < self.connect_timeout {
            return Err(invalid(
                "`provider_api_total_timeout` must not be shorter than `connect_timeout`".to_owned(),
            ));
        }
        for (key, value) in [
            ("max_response_bytes", self.max_response_bytes),
            ("oauth_max_response_bytes", self.oauth_max_response_bytes),
            ("provider_api_max_response_bytes", self.provider_api_max_response_bytes),
        ] {
            if value == 0 {
                return Err(invalid(format!("`{key}` must be greater than zero")));
            }
        }
        if self.max_concurrent_lookups == 0 {
            return Err(invalid("`max_concurrent_lookups` must be greater than zero".to_owned()));
        }
        if self.allowed_ports.contains(&0) {
            return Err(invalid("`allowed_ports` must not contain 0".to_owned()));
        }
        for host in &self.allow_hosts {
            let plausible = !host.is_empty()
                && host == &host.to_ascii_lowercase()
                && !host.contains(['/', ':', '*', '@', ' '])
                && !host.starts_with('.')
                && !host.ends_with('.');
            if !plausible {
                return Err(invalid(format!(
                    "`allow_hosts` entry `{host}` must be a lowercase host name without scheme, port or wildcard"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(value: serde_json::Value) -> EgressConfig {
        davhaven_ports::parse_config(PLUGIN, value).unwrap()
    }

    #[test]
    fn defaults_are_the_plan_values() {
        let config = parse(serde_json::json!({}));
        assert!(!config.allow_http);
        assert_eq!(config.connect_timeout, Duration::from_secs(5));
        assert_eq!(config.total_timeout, Duration::from_secs(10));
        assert_eq!(config.max_response_bytes, 65_536);
        assert_eq!(config.oauth_max_response_bytes, 262_144);
        assert_eq!(config.provider_api_max_response_bytes, 8 * 1024 * 1024);
        assert_eq!(config.provider_api_total_timeout, Duration::from_secs(30));
        assert_eq!(config, EgressConfig::default());
        config.validate().unwrap();
    }

    #[test]
    fn ranges_and_hosts_parse() {
        let config = parse(serde_json::json!({
            "allow_cidrs": ["10.20.0.0/16", "fd00::/8"],
            "deny_cidrs": ["203.0.113.0/24"],
            "allow_hosts": ["hooks.internal.example"],
            "connect_timeout": "2s",
            "total_timeout": "30s",
        }));
        assert_eq!(config.allow_cidrs.len(), 2);
        assert_eq!(config.deny_cidrs[0].to_string(), "203.0.113.0/24");
        config.validate().unwrap();
        for bad in [
            serde_json::json!({"allow_cidrs": ["10.0.0.0/33"]}),
            serde_json::json!({"allow_http": "yes"}),
        ] {
            assert!(davhaven_ports::parse_config::<EgressConfig>(PLUGIN, bad).is_err());
        }
    }

    #[test]
    fn validation_names_the_key() {
        for (value, key) in [
            (serde_json::json!({"connect_timeout": "0s"}), "connect_timeout"),
            (serde_json::json!({"connect_timeout": "20s"}), "total_timeout"),
            (serde_json::json!({"max_response_bytes": 0}), "max_response_bytes"),
            (
                serde_json::json!({"max_concurrent_lookups": 0}),
                "max_concurrent_lookups",
            ),
            (serde_json::json!({"allowed_ports": [443, 0]}), "allowed_ports"),
            (
                serde_json::json!({"oauth_max_response_bytes": 0}),
                "oauth_max_response_bytes",
            ),
            (
                serde_json::json!({"provider_api_max_response_bytes": 0}),
                "provider_api_max_response_bytes",
            ),
            (
                serde_json::json!({"provider_api_total_timeout": "1s", "connect_timeout": "2s", "total_timeout": "3s"}),
                "provider_api_total_timeout",
            ),
            (serde_json::json!({"allow_hosts": ["Example.org"]}), "allow_hosts"),
            (
                serde_json::json!({"allow_hosts": ["https://example.org"]}),
                "allow_hosts",
            ),
            (serde_json::json!({"allow_hosts": ["*.example.org"]}), "allow_hosts"),
        ] {
            let error = parse(value).validate().unwrap_err().to_string();
            assert!(error.contains(key), "{key}: {error}");
        }
    }
}
