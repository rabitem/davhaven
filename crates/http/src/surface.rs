//! The protocol surfaces that are mounted behind the edge layers.
//!
//! A surface is one of the protocol crates (`dav`, `api`, `web`, `mcp`). The edge layers behave the same for all of
//! them; what differs is the form of error responses, the credential scheme and the metric label, which is what
//! [`Surface`] selects.

use core::fmt;

/// A protocol surface served by one of the protocol crates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Surface {
    /// WebDAV and CalDAV (`/dav/…`) and the well-known redirect.
    Dav,
    /// The management API (`/api/v1/…`).
    Api,
    /// RSVP pages, subscription feeds, the OAuth callback and static assets.
    Web,
    /// The MCP endpoint (`/mcp`).
    Mcp,
}

impl Surface {
    /// Every surface.
    pub const ALL: [Self; 4] = [Self::Dav, Self::Api, Self::Web, Self::Mcp];

    /// The metric label and log field value: `dav`, `api`, `web` or `mcp`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dav => "dav",
            Self::Api => "api",
            Self::Web => "web",
            Self::Mcp => "mcp",
        }
    }
}

impl fmt::Display for Surface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_the_route_group_names() {
        let labels: Vec<&str> = Surface::ALL.iter().map(|surface| surface.as_str()).collect();
        assert_eq!(labels, vec!["dav", "api", "web", "mcp"]);
        assert_eq!(Surface::Api.to_string(), "api");
    }
}
