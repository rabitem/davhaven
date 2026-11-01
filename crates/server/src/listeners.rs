//! HTTP listeners and their route groups.
//!
//! The server serves three listeners by default (PLAN 2.5): `public` (the well-known redirect, DAV and the web
//! pages), `internal` (the management API and MCP) and `ops` (health, readiness and metrics). A deployment may
//! rebind them, give a listener other route groups (merging everything onto one listener is a list of six
//! groups) or disable it. Every route group is served by at most one listener.
//!
//! This module defines the configuration; the listeners themselves are started by [`crate::server::start`] and
//! served by [`crate::connection::serve`]. A port of 0 binds a free port (tests, and the address is logged).

use core::fmt;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use davhaven_app::config::ConfigError;
use schemars::JsonSchema;
use serde::Deserialize;

/// A group of routes a listener can serve (PLAN 2.5, "Route group").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum RouteGroup {
    /// `/.well-known/caldav`.
    Wellknown,
    /// `/dav/…`.
    Dav,
    /// RSVP pages, feeds, the OAuth callback and static assets.
    Web,
    /// `/api/v1/…`.
    Api,
    /// `/mcp`.
    Mcp,
    /// `/healthz`, `/readyz`, `/metrics`.
    Ops,
}

impl RouteGroup {
    /// Every group.
    pub const ALL: [Self; 6] = [Self::Wellknown, Self::Dav, Self::Web, Self::Api, Self::Mcp, Self::Ops];

    /// The configuration spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Wellknown => "wellknown",
            Self::Dav => "dav",
            Self::Web => "web",
            Self::Api => "api",
            Self::Mcp => "mcp",
            Self::Ops => "ops",
        }
    }
}

impl fmt::Display for RouteGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The three listeners of the default setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ListenerName {
    /// Faces clients: well-known, DAV and web pages.
    Public,
    /// Faces integrations: the management API and MCP.
    Internal,
    /// Faces operators and monitoring: health, readiness and metrics.
    Ops,
}

impl ListenerName {
    /// The name in the configuration (`listeners.<name>`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Ops => "ops",
        }
    }

    /// The address the listener binds to unless configured: the public listener on all interfaces, the others on
    /// the loopback interface (a deployment that exposes them says so explicitly).
    pub const fn default_bind(self) -> SocketAddr {
        match self {
            Self::Public => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080),
            Self::Internal => SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8081),
            Self::Ops => SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9090),
        }
    }

    /// The route groups the listener serves unless configured.
    pub fn default_routes(self) -> Vec<RouteGroup> {
        match self {
            Self::Public => vec![RouteGroup::Wellknown, RouteGroup::Dav, RouteGroup::Web],
            Self::Internal => vec![RouteGroup::Api, RouteGroup::Mcp],
            Self::Ops => vec![RouteGroup::Ops],
        }
    }
}

/// One entry of `[server.listeners]`. Absent values take the defaults of the listener's name.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ListenerConfig {
    /// Whether the listener is started. A disabled listener's default route groups are not served at all.
    pub enabled: bool,
    /// The address to bind: `0.0.0.0:8080` for `public`, `127.0.0.1:8081` for `internal`, `127.0.0.1:9090` for
    /// `ops`.
    pub bind: Option<SocketAddr>,
    /// The route groups to serve: `wellknown`, `dav`, `web` for `public`, `api`, `mcp` for `internal`, `ops` for
    /// `ops`.
    pub routes: Option<Vec<RouteGroup>>,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind: None,
            routes: None,
        }
    }
}

/// A listener with every default applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedListener {
    /// Which listener it is.
    pub name: ListenerName,
    /// The address to bind.
    pub bind: SocketAddr,
    /// The route groups to serve, without duplicates, in group order.
    pub routes: Vec<RouteGroup>,
}

/// The `[server.listeners]` table.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ListenersConfig {
    /// The listener for clients.
    pub public: ListenerConfig,
    /// The listener for integrations.
    pub internal: ListenerConfig,
    /// The listener for operations.
    pub ops: ListenerConfig,
}

impl ListenersConfig {
    /// The enabled listeners with defaults applied.
    pub fn resolved(&self) -> Vec<ResolvedListener> {
        [
            (ListenerName::Public, &self.public),
            (ListenerName::Internal, &self.internal),
            (ListenerName::Ops, &self.ops),
        ]
        .into_iter()
        .filter(|(_, config)| config.enabled)
        .map(|(name, config)| {
            let groups: BTreeSet<RouteGroup> = config
                .routes
                .clone()
                .unwrap_or_else(|| name.default_routes())
                .into_iter()
                .collect();
            ResolvedListener {
                name,
                bind: config.bind.unwrap_or_else(|| name.default_bind()),
                routes: groups.into_iter().collect(),
            }
        })
        .collect()
    }

    /// Checks the listeners: every enabled listener serves something, no route group is served twice and no two
    /// listeners bind the same address.
    ///
    /// # Errors
    ///
    /// A [`ConfigError`] for `server.listeners` naming the problem.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let listeners = self.resolved();
        let mut groups = BTreeSet::new();
        let mut binds = BTreeSet::new();
        for listener in &listeners {
            if listener.routes.is_empty() {
                return Err(ConfigError::new(
                    "server.listeners",
                    listener.name.as_str(),
                    "an enabled listener needs at least one route group (or `enabled = false`)",
                ));
            }
            // Port 0 asks the operating system for a free port, so two such listeners cannot clash.
            if listener.bind.port() != 0 && !binds.insert(listener.bind) {
                return Err(ConfigError::new(
                    "server.listeners",
                    listener.name.as_str(),
                    "two listeners bind the same address",
                ));
            }
            for group in &listener.routes {
                if !groups.insert(*group) {
                    return Err(ConfigError::new(
                        "server.listeners",
                        listener.name.as_str(),
                        "a route group is served by more than one listener",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> ListenersConfig {
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn defaults_are_the_plan_listeners() {
        let resolved = ListenersConfig::default().resolved();
        let summary: Vec<(&str, String, Vec<&str>)> = resolved
            .iter()
            .map(|listener| {
                (
                    listener.name.as_str(),
                    listener.bind.to_string(),
                    listener.routes.iter().map(|group| group.as_str()).collect(),
                )
            })
            .collect();
        assert_eq!(
            summary,
            vec![
                ("public", "0.0.0.0:8080".to_owned(), vec!["wellknown", "dav", "web"]),
                ("internal", "127.0.0.1:8081".to_owned(), vec!["api", "mcp"]),
                ("ops", "127.0.0.1:9090".to_owned(), vec!["ops"]),
            ]
        );
        ListenersConfig::default().validate().unwrap();
    }

    #[test]
    fn partial_tables_keep_the_defaults_of_their_listener() {
        let config = parse(r#"{"public": {"bind": "0.0.0.0:9000"}, "ops": {"routes": ["ops", "api"]}}"#);
        let resolved = config.resolved();
        assert_eq!(resolved[0].bind.port(), 9000);
        assert_eq!(
            resolved[0].routes,
            vec![RouteGroup::Wellknown, RouteGroup::Dav, RouteGroup::Web]
        );
        assert_eq!(resolved[2].routes, vec![RouteGroup::Api, RouteGroup::Ops]);
        let error = config.validate().unwrap_err();
        assert_eq!(
            (error.section(), error.key()),
            ("server.listeners", "ops"),
            "the api group is served twice"
        );
    }

    #[test]
    fn listeners_can_be_merged_or_disabled() {
        let merged = parse(
            r#"{"public": {"routes": ["wellknown", "dav", "web", "api", "mcp", "ops"]},
                "internal": {"enabled": false}, "ops": {"enabled": false}}"#,
        );
        merged.validate().unwrap();
        assert_eq!(merged.resolved().len(), 1);
        assert_eq!(merged.resolved()[0].routes.len(), 6);
        let disabled = parse(r#"{"internal": {"enabled": false}}"#);
        disabled.validate().unwrap();
        assert_eq!(disabled.resolved().len(), 2);
    }

    #[test]
    fn nonsense_is_refused() {
        let empty = parse(r#"{"ops": {"routes": []}}"#);
        assert!(empty.validate().unwrap_err().reason().contains("at least one"));
        let clash = parse(r#"{"internal": {"bind": "0.0.0.0:8080"}}"#);
        assert!(clash.validate().unwrap_err().reason().contains("same address"));
        let ephemeral = parse(
            r#"{"public": {"bind": "127.0.0.1:0"}, "internal": {"bind": "127.0.0.1:0"}, "ops": {"bind": "127.0.0.1:0"}}"#,
        );
        ephemeral.validate().unwrap();
        assert!(serde_json::from_str::<ListenersConfig>(r#"{"public": {"routes": ["admin"]}}"#).is_err());
        assert!(serde_json::from_str::<ListenersConfig>(r#"{"public": {"bind": "not an address"}}"#).is_err());
        assert!(serde_json::from_str::<ListenersConfig>(r#"{"external": {}}"#).is_err());
        assert_eq!(RouteGroup::ALL.len(), 6);
    }
}
