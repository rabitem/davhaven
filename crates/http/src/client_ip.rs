//! Client IP resolution from `X-Forwarded-For` behind trusted proxies.
//!
//! The client address feeds the failure backoff of authentication, rate limits and the audit log (as a hash). It
//! must not be spoofable, so `X-Forwarded-For` counts only when the TCP peer is one of the configured trusted
//! proxies (`server.trusted_proxies`, PLAN 2.5), and then the **rightmost entry that is not itself a trusted proxy**
//! is the client: every hop appends the address it received the request from, so entries to the left of the first
//! untrusted one were written by the client and can be anything.
//!
//! The layer stores the result as a [`ClientIp`] extension; the peer address comes from axum's `ConnectInfo`
//! (the server serves with `into_make_service_with_connect_info`). Without it (in-process tests) the client IP is
//! unknown.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::Extensions;
use axum::http::header::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;
use ipnet::IpNet;

/// The resolved client address of a request, stored in the request extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub Option<IpAddr>);

/// The networks whose `X-Forwarded-For` entries are believed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies {
    networks: Vec<IpNet>,
}

impl TrustedProxies {
    /// The proxies of the configuration; an empty list trusts nobody and the TCP peer is always the client.
    pub const fn new(networks: Vec<IpNet>) -> Self {
        Self { networks }
    }

    /// Whether `ip` belongs to a trusted network. IPv4-mapped IPv6 addresses match their IPv4 networks.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.networks.iter().any(|network| network.contains(&ip))
    }

    /// The client of a request that arrived from `peer` with the given `X-Forwarded-For` header values.
    ///
    /// * An untrusted peer is the client; its header is ignored.
    /// * Behind a trusted peer the entries are read from the right: trusted proxies are skipped, the first other
    ///   address is the client. If every entry is trusted, the leftmost one is.
    /// * An entry that is not an IP address ends the walk at the proxy that wrote it: the peer is the client then.
    /// * Without a peer address the client is unknown.
    pub fn client_ip(&self, peer: Option<IpAddr>, forwarded_for: &[&str]) -> Option<IpAddr> {
        let peer = peer?.to_canonical();
        if !self.contains(peer) {
            return Some(peer);
        }
        let mut client = peer;
        let entries = forwarded_for.iter().flat_map(|value| value.split(',')).map(str::trim);
        for entry in entries.rev() {
            match entry.parse::<IpAddr>() {
                Ok(ip) if self.contains(ip) => client = ip.to_canonical(),
                Ok(ip) => return Some(ip.to_canonical()),
                Err(_) => return Some(peer),
            }
        }
        Some(client)
    }
}

/// The values of every `X-Forwarded-For` header line.
fn forwarded_for(headers: &HeaderMap) -> Vec<&str> {
    headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect()
}

/// The resolved client address stored in `extensions`, if the layer ran and knew it.
pub fn client_ip_of(extensions: &Extensions) -> Option<IpAddr> {
    extensions.get::<ClientIp>().and_then(|client| client.0)
}

/// The layer function of the client address; mount it with
/// `axum::middleware::from_fn_with_state(trusted_proxies, resolve_client_ip)`.
pub async fn resolve_client_ip(
    State(proxies): State<Arc<TrustedProxies>>,
    mut request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| address.ip());
    let client = proxies.client_ip(peer, &forwarded_for(request.headers()));
    request.extensions_mut().insert(ClientIp(client));
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::routing::get;
    use tower::ServiceExt as _;

    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn proxies(networks: &[&str]) -> TrustedProxies {
        TrustedProxies::new(networks.iter().map(|text| text.parse().unwrap()).collect())
    }

    #[test]
    fn an_untrusted_peer_is_the_client_whatever_the_header_says() {
        let trusted = proxies(&["10.0.0.0/8"]);
        let client = trusted.client_ip(Some(ip("203.0.113.9")), &["198.51.100.1"]);
        assert_eq!(client, Some(ip("203.0.113.9")));
        assert_eq!(
            TrustedProxies::default().client_ip(Some(ip("10.1.1.1")), &["1.2.3.4"]),
            Some(ip("10.1.1.1"))
        );
    }

    #[test]
    fn behind_a_trusted_peer_the_rightmost_untrusted_entry_is_the_client() {
        let trusted = proxies(&["10.0.0.0/8", "192.168.0.0/16"]);
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(trusted.client_ip(peer, &["198.51.100.7"]), Some(ip("198.51.100.7")));
        // The client forged the leftmost entries; the proxy appended the real address on the right.
        assert_eq!(
            trusted.client_ip(peer, &["6.6.6.6, 7.7.7.7", "198.51.100.7, 10.0.0.2"]),
            Some(ip("198.51.100.7"))
        );
        assert_eq!(
            trusted.client_ip(peer, &["198.51.100.7, 192.168.1.1, 10.2.2.2"]),
            Some(ip("198.51.100.7"))
        );
    }

    #[test]
    fn all_trusted_hops_make_the_leftmost_entry_the_client() {
        let trusted = proxies(&["10.0.0.0/8"]);
        assert_eq!(
            trusted.client_ip(Some(ip("10.0.0.1")), &["10.9.9.9, 10.8.8.8"]),
            Some(ip("10.9.9.9"))
        );
        assert_eq!(trusted.client_ip(Some(ip("10.0.0.1")), &[]), Some(ip("10.0.0.1")));
    }

    #[test]
    fn garbage_entries_stop_the_walk_at_the_proxy() {
        let trusted = proxies(&["10.0.0.0/8"]);
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(trusted.client_ip(peer, &["1.2.3.4, unknown"]), peer);
        assert_eq!(trusted.client_ip(peer, &["1.2.3.4, 10.0.0.9:8080"]), peer);
        assert_eq!(trusted.client_ip(peer, &["1.2.3.4,"]), peer);
    }

    #[test]
    fn ipv6_and_mapped_addresses_are_handled() {
        let trusted = proxies(&["10.0.0.0/8", "fd00::/8"]);
        assert!(trusted.contains(ip("::ffff:10.1.2.3")));
        assert!(trusted.contains(ip("fd12::1")));
        assert!(!trusted.contains(ip("2001:db8::1")));
        assert_eq!(
            trusted.client_ip(Some(ip("fd00::1")), &["2001:db8::5, fd00::2"]),
            Some(ip("2001:db8::5"))
        );
        assert_eq!(
            trusted.client_ip(Some(ip("::ffff:203.0.113.4")), &[]),
            Some(ip("203.0.113.4"))
        );
    }

    #[test]
    fn an_unknown_peer_means_an_unknown_client() {
        assert_eq!(proxies(&["10.0.0.0/8"]).client_ip(None, &["1.2.3.4"]), None);
    }

    async fn show(request: Request) -> String {
        client_ip_of(request.extensions())
            .map(|ip| ip.to_string())
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn the_layer_combines_the_peer_and_the_header() {
        let state = Arc::new(proxies(&["10.0.0.0/8"]));
        let app = Router::new()
            .route("/", get(show))
            .layer(axum::middleware::from_fn_with_state(state, resolve_client_ip));
        let mut request = Request::get("/")
            .header("x-forwarded-for", "9.9.9.9, 198.51.100.4")
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(ip("10.0.0.7"), 40000)));
        let response = app.clone().oneshot(request).await.unwrap();
        let bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&bytes[..], b"198.51.100.4");
        let without_peer = app
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let bytes = http_body_util::BodyExt::collect(without_peer.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert!(bytes.is_empty());
    }
}
