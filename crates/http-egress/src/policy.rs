//! The egress policy: schemes, address ranges and host allow lists.
//!
//! Every outbound request is checked twice: the URL before anything happens (scheme, credentials, literal
//! addresses) and every address a host name resolves to, at the moment the connection is made
//! ([`crate::resolver`]). Both checks use the same [`EgressPolicy`], so a URL cannot get past the first by naming
//! an address in an unusual notation, and cannot get past the second by changing what its DNS records say.
//!
//! # What is denied
//!
//! Only global unicast addresses are allowed by default. Everything else is classified ([`AddressClass`]) and
//! refused: loopback, private, link-local, carrier-grade NAT, unique-local, documentation, benchmarking,
//! reserved, multicast and unspecified ranges for IPv4 and IPv6, and the IPv4 address embedded in IPv4-mapped,
//! IPv4-compatible, NAT64 and 6to4 IPv6 addresses is judged by the IPv4 rules. The well-known cloud metadata
//! addresses are refused on top of that, and `allow_cidrs` never reaches them.
//!
//! # What a deployment can change
//!
//! * `allow_cidrs` and `allow_hosts` permit non-global ranges (a webhook receiver in the deployment's own
//!   network). They do not permit multicast, unspecified, broadcast or metadata addresses.
//! * `deny_cidrs` adds ranges to the denials and always wins over the allow lists.
//! * `allow_http` permits the `http` scheme.

use core::fmt;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use url::{Host, Url};

use crate::config::EgressConfig;

/// The longest URL the policy accepts.
pub const MAX_URL_LENGTH: usize = 2048;

/// Addresses of cloud metadata services. They are denied whatever `allow_cidrs` says.
const METADATA_V4: [Ipv4Addr; 6] = [
    // AWS, Azure, GCP, DigitalOcean, OpenStack and most others.
    Ipv4Addr::new(169, 254, 169, 254),
    // AWS ECS task metadata.
    Ipv4Addr::new(169, 254, 170, 2),
    // Alibaba Cloud.
    Ipv4Addr::new(100, 100, 100, 200),
    // Azure wire server and health probes (a public address).
    Ipv4Addr::new(168, 63, 129, 16),
    // Oracle Cloud.
    Ipv4Addr::new(192, 0, 0, 192),
    // Kubernetes API of some managed clusters and link-local DNS of cloud resolvers.
    Ipv4Addr::new(169, 254, 169, 253),
];

/// AWS IPv6 metadata endpoint.
const METADATA_V6: [Ipv6Addr; 1] = [Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)];

/// The category of an address that is not a global unicast address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressClass {
    /// `0.0.0.0/8` and `::`.
    Unspecified,
    /// `127.0.0.0/8` and `::1`.
    Loopback,
    /// RFC 1918 ranges and the deprecated IPv6 site-local range.
    Private,
    /// `169.254.0.0/16` and `fe80::/10`.
    LinkLocal,
    /// A cloud metadata address.
    Metadata,
    /// `100.64.0.0/10` (carrier-grade NAT).
    CarrierGradeNat,
    /// `fc00::/7`.
    UniqueLocal,
    /// `224.0.0.0/4` and `ff00::/8`.
    Multicast,
    /// `255.255.255.255`.
    Broadcast,
    /// Documentation ranges.
    Documentation,
    /// Benchmarking ranges.
    Benchmarking,
    /// Teredo, local-use NAT64, discard-only and other special-purpose or not yet allocated ranges.
    Reserved,
    /// A range the deployment denies (`deny_cidrs`).
    Configured,
}

impl AddressClass {
    /// A stable `snake_case` name for logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Loopback => "loopback",
            Self::Private => "private",
            Self::LinkLocal => "link_local",
            Self::Metadata => "metadata",
            Self::CarrierGradeNat => "carrier_grade_nat",
            Self::UniqueLocal => "unique_local",
            Self::Multicast => "multicast",
            Self::Broadcast => "broadcast",
            Self::Documentation => "documentation",
            Self::Benchmarking => "benchmarking",
            Self::Reserved => "reserved",
            Self::Configured => "configured",
        }
    }

    /// Whether no allow list can permit the class: these are never valid destinations.
    const fn is_never_allowed(self) -> bool {
        matches!(
            self,
            Self::Unspecified | Self::Multicast | Self::Broadcast | Self::Metadata | Self::Configured
        )
    }
}

impl fmt::Display for AddressClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

/// Why the policy refuses a target. The text is for operators and logs; it never reaches a client.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyViolation {
    /// The scheme is not `https` (or `http` when allowed).
    #[error("egress policy: the scheme `{0}` is not allowed")]
    Scheme(String),
    /// The URL has no host.
    #[error("egress policy: the URL has no host")]
    NoHost,
    /// The URL carries a user name or password.
    #[error("egress policy: the URL carries credentials")]
    Credentials,
    /// The URL is longer than [`MAX_URL_LENGTH`].
    #[error("egress policy: the URL is too long")]
    TooLong,
    /// The port of the target is not in the list of allowed ports.
    #[error("egress policy: the port {0} is not allowed")]
    Port(u16),
    /// The target address is in a denied range.
    #[error("egress policy: the target address is in a denied range ({0})")]
    Address(AddressClass),
    /// The host name has no address.
    #[error("egress policy: the host name does not resolve")]
    Unresolvable,
}

/// What a checked URL points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A literal address that passed the checks.
    Address(IpAddr),
    /// A host name (lowercase, without a trailing dot); its addresses are checked when it is resolved.
    Name(String),
}

/// The decisions of the egress policy.
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    allow_http: bool,
    allow_cidrs: Vec<IpNet>,
    allow_hosts: BTreeSet<String>,
    deny_cidrs: Vec<IpNet>,
    allowed_ports: BTreeSet<u16>,
}

impl EgressPolicy {
    /// The policy of a configuration.
    pub fn new(config: &EgressConfig) -> Self {
        Self {
            allow_http: config.allow_http,
            allow_cidrs: config.allow_cidrs.clone(),
            allow_hosts: config.allow_hosts.iter().map(|host| normalize_host(host)).collect(),
            deny_cidrs: config.deny_cidrs.clone(),
            allowed_ports: config.allowed_ports.iter().copied().collect(),
        }
    }

    /// Checks the parts of a URL that need no DNS: the scheme, the absence of credentials, the host and, for a
    /// literal address, the address itself.
    ///
    /// The `url` crate follows the WHATWG URL standard, so `2130706433`, `0x7f.1`, `017700000001`, `127.1` and
    /// percent-encoded or full-width digits all arrive here as the IPv4 address `127.0.0.1`.
    ///
    /// # Errors
    ///
    /// The [`PolicyViolation`] that applies.
    pub fn check_url(&self, url: &Url) -> Result<Target, PolicyViolation> {
        if url.as_str().len() > MAX_URL_LENGTH {
            return Err(PolicyViolation::TooLong);
        }
        match url.scheme() {
            "https" => {}
            "http" if self.allow_http => {}
            other => return Err(PolicyViolation::Scheme(other.to_owned())),
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(PolicyViolation::Credentials);
        }
        if !self.allowed_ports.is_empty() {
            let port = url.port_or_known_default().unwrap_or(0);
            if !self.allowed_ports.contains(&port) {
                return Err(PolicyViolation::Port(port));
            }
        }
        match url.host() {
            None => Err(PolicyViolation::NoHost),
            Some(Host::Ipv4(address)) => self
                .check_address(IpAddr::V4(address), None)
                .map(|()| Target::Address(IpAddr::V4(address))),
            Some(Host::Ipv6(address)) => self
                .check_address(IpAddr::V6(address), None)
                .map(|()| Target::Address(IpAddr::V6(address))),
            Some(Host::Domain(name)) => {
                let name = normalize_host(name);
                if name.is_empty() {
                    Err(PolicyViolation::NoHost)
                } else {
                    Ok(Target::Name(name))
                }
            }
        }
    }

    /// Checks one address. `host` is the name it was resolved from, which makes `allow_hosts` apply.
    ///
    /// # Errors
    ///
    /// [`PolicyViolation::Address`] with the class of the denied address.
    pub fn check_address(&self, address: IpAddr, host: Option<&str>) -> Result<(), PolicyViolation> {
        let embedded = embedded_v4(address);
        let candidates = [Some(address), embedded.map(IpAddr::V4)];
        if candidates
            .iter()
            .flatten()
            .any(|candidate| self.deny_cidrs.iter().any(|net| net.contains(candidate)))
        {
            return Err(PolicyViolation::Address(AddressClass::Configured));
        }
        let Some(class) = classify(address) else {
            return Ok(());
        };
        if class.is_never_allowed() {
            return Err(PolicyViolation::Address(class));
        }
        let allowed_by_range = candidates
            .iter()
            .flatten()
            .any(|candidate| self.allow_cidrs.iter().any(|net| net.contains(candidate)));
        let allowed_by_host = host.is_some_and(|name| self.allow_hosts.contains(&normalize_host(name)));
        if allowed_by_range || allowed_by_host {
            Ok(())
        } else {
            Err(PolicyViolation::Address(class))
        }
    }
}

/// Lowercases a host name and removes the trailing dot of a fully qualified name.
pub(crate) fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// An IPv4 address embedded in an IPv6 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Embedded {
    /// IPv4-mapped (`::ffff:a.b.c.d`) and IPv4-compatible (`::a.b.c.d`) addresses: nothing legitimate sends
    /// them, so even a global embedded address is refused.
    Mapped(Ipv4Addr),
    /// NAT64 (`64:ff9b::/96`) and 6to4 (`2002::/16`) addresses: they route to the embedded address, so the
    /// embedded address decides.
    Translated(Ipv4Addr),
}

impl Embedded {
    const fn v4(self) -> Ipv4Addr {
        match self {
            Self::Mapped(address) | Self::Translated(address) => address,
        }
    }
}

/// The IPv4 address an IPv6 address stands for, if it embeds one.
fn embedded(address: Ipv6Addr) -> Option<Embedded> {
    let [s0, s1, s2, s3, s4, s5, s6, s7] = address.segments();
    let v4_from = |high: u16, low: u16| {
        let [a, b] = high.to_be_bytes();
        let [c, d] = low.to_be_bytes();
        Ipv4Addr::new(a, b, c, d)
    };
    let zero_prefix = s0 == 0 && s1 == 0 && s2 == 0 && s3 == 0 && s4 == 0;
    // `::ffff:a.b.c.d` (mapped).
    if zero_prefix && s5 == 0xffff {
        return Some(Embedded::Mapped(v4_from(s6, s7)));
    }
    // `::a.b.c.d` (compatible); `::` and `::1` are the unspecified and the loopback address.
    if zero_prefix && s5 == 0 && (s6 != 0 || s7 > 1) {
        return Some(Embedded::Mapped(v4_from(s6, s7)));
    }
    // 64:ff9b::/96 (RFC 6052).
    if s0 == 0x0064 && s1 == 0xff9b && s2 == 0 && s3 == 0 && s4 == 0 && s5 == 0 {
        return Some(Embedded::Translated(v4_from(s6, s7)));
    }
    // 2002::/16 (6to4): the IPv4 address follows the prefix.
    if s0 == 0x2002 {
        return Some(Embedded::Translated(v4_from(s1, s2)));
    }
    None
}

fn embedded_v4(address: IpAddr) -> Option<Ipv4Addr> {
    match address {
        IpAddr::V6(v6) => embedded(v6).map(Embedded::v4),
        IpAddr::V4(_) => None,
    }
}

/// The class of an address, or `None` for a global unicast address.
pub fn classify(address: IpAddr) -> Option<AddressClass> {
    match address {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(address: Ipv4Addr) -> Option<AddressClass> {
    if METADATA_V4.contains(&address) {
        return Some(AddressClass::Metadata);
    }
    let [a, b, c, _] = address.octets();
    let class = match (a, b, c) {
        (0, _, _) => AddressClass::Unspecified,
        (10, _, _) | (172, 16..=31, _) | (192, 168, _) => AddressClass::Private,
        (100, 64..=127, _) => AddressClass::CarrierGradeNat,
        (127, _, _) => AddressClass::Loopback,
        (169, 254, _) => AddressClass::LinkLocal,
        (192, 0, 2) | (198, 51, 100) | (203, 0, 113) => AddressClass::Documentation,
        (198, 18 | 19, _) => AddressClass::Benchmarking,
        (224..=239, _, _) => AddressClass::Multicast,
        (255, 255, 255) if address == Ipv4Addr::BROADCAST => AddressClass::Broadcast,
        (192, 0, 0) | (192, 88, 99) | (240..=255, _, _) => AddressClass::Reserved,
        _ => return None,
    };
    Some(class)
}

fn classify_v6(address: Ipv6Addr) -> Option<AddressClass> {
    if METADATA_V6.contains(&address) {
        return Some(AddressClass::Metadata);
    }
    if address.is_unspecified() {
        return Some(AddressClass::Unspecified);
    }
    if address.is_loopback() {
        return Some(AddressClass::Loopback);
    }
    if let Some(found) = embedded(address) {
        return match (found, classify_v4(found.v4())) {
            (_, Some(class)) => Some(class),
            (Embedded::Translated(_), None) => None,
            (Embedded::Mapped(_), None) => Some(AddressClass::Reserved),
        };
    }
    let segments = address.segments();
    let first = segments[0];
    let class = match first {
        0xff00..=0xffff => AddressClass::Multicast,
        0xfe80..=0xfebf => AddressClass::LinkLocal,
        0xfec0..=0xfeff => AddressClass::Private,
        0xfc00..=0xfdff => AddressClass::UniqueLocal,
        // 2001::/32 Teredo, 2001:2::/48 benchmarking, 2001:db8::/32 documentation, 2001:10::/28 and
        // 2001:20::/28 ORCHID.
        0x2001 if segments[1] == 0 => AddressClass::Reserved,
        0x2001 if segments[1] == 2 && segments[2] == 0 => AddressClass::Benchmarking,
        0x2001 if segments[1] == 0x0db8 => AddressClass::Documentation,
        0x2001 if (0x0010..=0x002f).contains(&segments[1]) => AddressClass::Reserved,
        // 3fff::/20 documentation (RFC 9637).
        0x3fff if segments[1] <= 0x0fff => AddressClass::Documentation,
        // Global unicast is 2000::/3 today. Everything else, including 64:ff9b:1::/48 (local-use NAT64), 100::/64
        // (discard-only) and 5f00::/16 (SRv6), is not allocated for the public Internet.
        0x2000..=0x3fff => return None,
        _ => AddressClass::Reserved,
    };
    Some(class)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> EgressPolicy {
        EgressPolicy::new(&EgressConfig::default())
    }

    fn with(edit: impl FnOnce(&mut EgressConfig)) -> EgressPolicy {
        let mut config = EgressConfig::default();
        edit(&mut config);
        EgressPolicy::new(&config)
    }

    #[test]
    fn the_list_of_ports_limits_the_targets_when_it_is_set() {
        let url = |text: &str| Url::parse(text).unwrap();
        // No list: every port.
        for text in ["https://8.8.8.8/", "https://8.8.8.8:8443/", "https://8.8.8.8:22/"] {
            assert!(policy().check_url(&url(text)).is_ok(), "{text}");
        }
        let only_443 = with(|config| config.allowed_ports = vec![443]);
        assert!(
            only_443.check_url(&url("https://8.8.8.8/")).is_ok(),
            "the default port of https"
        );
        assert!(only_443.check_url(&url("https://8.8.8.8:443/")).is_ok());
        for (text, port) in [
            ("https://8.8.8.8:8443/", 8443),
            ("https://8.8.8.8:22/", 22),
            ("https://hooks.example.org:25/", 25),
        ] {
            assert_eq!(
                only_443.check_url(&url(text)),
                Err(PolicyViolation::Port(port)),
                "{text}"
            );
        }
        let with_http = with(|config| {
            config.allow_http = true;
            config.allowed_ports = vec![80, 443];
        });
        assert!(
            with_http.check_url(&url("http://8.8.8.8/")).is_ok(),
            "the default port of http"
        );
    }

    fn net(text: &str) -> IpNet {
        text.parse().unwrap()
    }

    fn url(text: &str) -> Url {
        Url::parse(text).unwrap()
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn every_special_range_is_classified() {
        let cases = [
            ("0.0.0.0", AddressClass::Unspecified),
            ("0.1.2.3", AddressClass::Unspecified),
            ("10.0.0.1", AddressClass::Private),
            ("10.255.255.255", AddressClass::Private),
            ("172.16.0.1", AddressClass::Private),
            ("172.31.255.255", AddressClass::Private),
            ("192.168.1.1", AddressClass::Private),
            ("100.64.0.1", AddressClass::CarrierGradeNat),
            ("100.127.255.255", AddressClass::CarrierGradeNat),
            ("127.0.0.1", AddressClass::Loopback),
            ("127.255.255.254", AddressClass::Loopback),
            ("169.254.0.1", AddressClass::LinkLocal),
            ("169.254.169.254", AddressClass::Metadata),
            ("169.254.170.2", AddressClass::Metadata),
            ("100.100.100.200", AddressClass::Metadata),
            ("168.63.129.16", AddressClass::Metadata),
            ("192.0.0.192", AddressClass::Metadata),
            ("169.254.169.253", AddressClass::Metadata),
            ("192.0.0.1", AddressClass::Reserved),
            ("192.88.99.1", AddressClass::Reserved),
            ("192.0.2.1", AddressClass::Documentation),
            ("198.51.100.1", AddressClass::Documentation),
            ("203.0.113.1", AddressClass::Documentation),
            ("198.18.0.1", AddressClass::Benchmarking),
            ("198.19.255.255", AddressClass::Benchmarking),
            ("224.0.0.1", AddressClass::Multicast),
            ("239.255.255.255", AddressClass::Multicast),
            ("240.0.0.1", AddressClass::Reserved),
            ("255.255.255.255", AddressClass::Broadcast),
            ("::", AddressClass::Unspecified),
            ("::1", AddressClass::Loopback),
            ("fe80::1", AddressClass::LinkLocal),
            ("febf::1", AddressClass::LinkLocal),
            ("fec0::1", AddressClass::Private),
            ("fc00::1", AddressClass::UniqueLocal),
            ("fd12:3456::1", AddressClass::UniqueLocal),
            ("fd00:ec2::254", AddressClass::Metadata),
            ("ff02::1", AddressClass::Multicast),
            ("2001:db8::1", AddressClass::Documentation),
            ("2001::1", AddressClass::Reserved),
            ("2001:2::1", AddressClass::Benchmarking),
            ("2001:10::1", AddressClass::Reserved),
            ("3fff::1", AddressClass::Documentation),
            ("100::1", AddressClass::Reserved),
            ("64:ff9b:1::1", AddressClass::Reserved),
            ("4000::1", AddressClass::Reserved),
            ("::ffff:127.0.0.1", AddressClass::Loopback),
            ("::ffff:7f00:1", AddressClass::Loopback),
            ("::ffff:10.1.2.3", AddressClass::Private),
            ("::ffff:169.254.169.254", AddressClass::Metadata),
            ("::127.0.0.1", AddressClass::Loopback),
            ("::10.0.0.1", AddressClass::Private),
            ("64:ff9b::7f00:1", AddressClass::Loopback),
            ("64:ff9b::a9fe:a9fe", AddressClass::Metadata),
            ("2002:7f00:1::", AddressClass::Loopback),
            ("2002:0a00:0001::1", AddressClass::Private),
        ];
        for (text, expected) in cases {
            assert_eq!(classify(ip(text)), Some(expected), "{text}");
        }
    }

    #[test]
    fn global_unicast_addresses_are_not_classified() {
        for text in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "172.15.255.255",
            "172.32.0.1",
            "100.63.255.255",
            "100.128.0.1",
            "192.0.1.1",
            "198.17.255.255",
            "198.20.0.1",
            "2606:4700:4700::1111",
            "2a00:1450:4001:81b::200e",
            "2001:4860:4860::8888",
            "64:ff9b::808:808",
            "2002:0808:0808::1",
        ] {
            assert_eq!(classify(ip(text)), None, "{text}");
        }
        // The mapped or compatible form of a global address is not a normal destination.
        assert_eq!(classify(ip("::ffff:8.8.8.8")), Some(AddressClass::Reserved));
        assert_eq!(classify(ip("::8.8.8.8")), Some(AddressClass::Reserved));
    }

    #[test]
    fn schemes_credentials_and_hosts_are_checked_before_any_dns() {
        let policy = policy();
        assert_eq!(
            policy.check_url(&url("https://hooks.example.org/in")),
            Ok(Target::Name("hooks.example.org".to_owned()))
        );
        assert_eq!(
            policy.check_url(&url("https://Hooks.Example.ORG./in")),
            Ok(Target::Name("hooks.example.org".to_owned()))
        );
        assert_eq!(
            policy.check_url(&url("https://8.8.8.8/")),
            Ok(Target::Address(ip("8.8.8.8")))
        );
        assert_eq!(
            policy.check_url(&url("http://hooks.example.org/")),
            Err(PolicyViolation::Scheme("http".to_owned()))
        );
        for scheme in [
            "ftp://example.org/",
            "file:///etc/passwd",
            "gopher://example.org/",
            "ws://example.org/",
        ] {
            assert!(
                matches!(policy.check_url(&url(scheme)), Err(PolicyViolation::Scheme(_))),
                "{scheme}"
            );
        }
        assert_eq!(
            policy.check_url(&url("https://user:secret@hooks.example.org/")),
            Err(PolicyViolation::Credentials)
        );
        assert_eq!(
            policy.check_url(&url("https://user@hooks.example.org/")),
            Err(PolicyViolation::Credentials)
        );
        let long = format!("https://hooks.example.org/{}", "a".repeat(MAX_URL_LENGTH));
        assert_eq!(policy.check_url(&url(&long)), Err(PolicyViolation::TooLong));
        assert!(
            with(|c| c.allow_http = true)
                .check_url(&url("http://hooks.example.org/"))
                .is_ok()
        );
    }

    #[test]
    fn literal_addresses_in_every_notation_are_refused() {
        let policy = policy();
        for text in [
            "https://127.0.0.1/",
            "https://127.1/",
            "https://2130706433/",
            "https://0x7f000001/",
            "https://0x7f.0.0.1/",
            "https://017700000001/",
            "https://0177.0.0.1/",
            "https://127.0.0.1./",
            "https://%31%32%37.0.0.1/",
            "https://\u{ff11}\u{ff12}\u{ff17}.0.0.1/",
            "https://0/",
            "https://0.0.0.0/",
            "https://[::1]/",
            "https://[0:0:0:0:0:0:0:1]/",
            "https://[::ffff:127.0.0.1]/",
            "https://[::ffff:7f00:1]/",
            "https://[::127.0.0.1]/",
            "https://[64:ff9b::7f00:1]/",
            "https://[2002:7f00:1::]/",
            "https://[fe80::1]/",
            "https://[fd00:ec2::254]/",
            "https://10.0.0.1:8443/",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::ffff:169.254.169.254]/",
            "https://2852039166/",
            "https://100.100.100.200/",
            "https://168.63.129.16/",
            "https://255.255.255.255/",
        ] {
            assert!(
                matches!(policy.check_url(&url(text)), Err(PolicyViolation::Address(_))),
                "{text}: {:?}",
                policy.check_url(&url(text))
            );
        }
    }

    #[test]
    fn allow_lists_permit_private_space_but_never_metadata_or_multicast() {
        let policy = with(|config| {
            config.allow_cidrs = vec![
                net("10.20.0.0/16"),
                net("169.254.0.0/16"),
                net("127.0.0.0/8"),
                net("224.0.0.0/4"),
                net("fd00::/8"),
            ];
            config.allow_hosts = vec!["hooks.internal.example".to_owned()];
        });
        assert!(policy.check_address(ip("10.20.1.2"), None).is_ok());
        assert!(policy.check_address(ip("127.0.0.1"), None).is_ok());
        assert!(
            policy.check_address(ip("::ffff:10.20.1.2"), None).is_ok(),
            "the mapped form follows the IPv4 range"
        );
        assert!(policy.check_address(ip("fd00::5"), None).is_ok());
        assert_eq!(
            policy.check_address(ip("10.21.0.1"), None),
            Err(PolicyViolation::Address(AddressClass::Private))
        );
        assert_eq!(
            policy.check_address(ip("169.254.169.254"), None),
            Err(PolicyViolation::Address(AddressClass::Metadata)),
            "the allowed link-local range does not reach the metadata address"
        );
        assert!(policy.check_address(ip("169.254.1.1"), None).is_ok());
        assert_eq!(
            policy.check_address(ip("224.0.0.1"), None),
            Err(PolicyViolation::Address(AddressClass::Multicast))
        );
        assert_eq!(
            policy.check_address(ip("192.168.0.1"), None),
            Err(PolicyViolation::Address(AddressClass::Private))
        );
        // An allowed host name makes every non-global address it resolves to acceptable, with the same limits.
        assert!(
            policy
                .check_address(ip("192.168.0.1"), Some("hooks.internal.example"))
                .is_ok()
        );
        assert!(
            policy
                .check_address(ip("192.168.0.1"), Some("HOOKS.internal.example."))
                .is_ok()
        );
        assert_eq!(
            policy.check_address(ip("192.168.0.1"), Some("other.example")),
            Err(PolicyViolation::Address(AddressClass::Private))
        );
        assert_eq!(
            policy.check_address(ip("169.254.169.254"), Some("hooks.internal.example")),
            Err(PolicyViolation::Address(AddressClass::Metadata))
        );
        assert_eq!(
            policy.check_address(ip("0.0.0.0"), Some("hooks.internal.example")),
            Err(PolicyViolation::Address(AddressClass::Unspecified))
        );
    }

    #[test]
    fn deny_ranges_win_over_every_allowance() {
        let policy = with(|config| {
            config.allow_cidrs = vec![net("10.0.0.0/8")];
            config.deny_cidrs = vec![net("10.9.0.0/16"), net("203.0.113.0/24"), net("8.8.8.0/24")];
            config.allow_hosts = vec!["hooks.internal.example".to_owned()];
        });
        assert!(policy.check_address(ip("10.1.1.1"), None).is_ok());
        for text in ["10.9.1.1", "8.8.8.8", "::ffff:8.8.8.8", "::ffff:10.9.0.1"] {
            assert_eq!(
                policy.check_address(ip(text), None),
                Err(PolicyViolation::Address(AddressClass::Configured)),
                "{text}"
            );
        }
        assert_eq!(
            policy.check_address(ip("10.9.1.1"), Some("hooks.internal.example")),
            Err(PolicyViolation::Address(AddressClass::Configured))
        );
        assert!(policy.check_address(ip("8.8.4.4"), None).is_ok());
    }

    #[test]
    fn violations_and_classes_have_stable_names() {
        // The names are what operators search their logs for: a rename breaks their alerts.
        assert_eq!(
            PolicyViolation::Address(AddressClass::Loopback).to_string(),
            "egress policy: the target address is in a denied range (loopback)"
        );
        for (class, name) in [
            (AddressClass::Unspecified, "unspecified"),
            (AddressClass::Loopback, "loopback"),
            (AddressClass::Private, "private"),
            (AddressClass::LinkLocal, "link_local"),
            (AddressClass::Metadata, "metadata"),
            (AddressClass::CarrierGradeNat, "carrier_grade_nat"),
            (AddressClass::UniqueLocal, "unique_local"),
            (AddressClass::Multicast, "multicast"),
            (AddressClass::Broadcast, "broadcast"),
            (AddressClass::Documentation, "documentation"),
            (AddressClass::Benchmarking, "benchmarking"),
            (AddressClass::Reserved, "reserved"),
            (AddressClass::Configured, "configured"),
        ] {
            assert_eq!(class.as_str(), name);
            assert_eq!(class.to_string(), name);
        }
    }

    #[test]
    fn allowing_every_range_still_never_reaches_metadata_multicast_broadcast_or_unspecified_addresses() {
        // An operator who allows everything (a lab, a misconfiguration) still cannot reach these.
        let open = with(|config| {
            config.allow_cidrs = vec![net("0.0.0.0/0"), net("::/0")];
            config.allow_hosts = vec!["hooks.internal.example".to_owned()];
        });
        for text in [
            "10.0.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "fd00::1",
            "::ffff:192.168.0.1",
            "100.64.0.1",
        ] {
            assert!(open.check_address(ip(text), None).is_ok(), "{text}");
        }
        for (text, class) in [
            ("169.254.169.254", AddressClass::Metadata),
            ("100.100.100.200", AddressClass::Metadata),
            ("fd00:ec2::254", AddressClass::Metadata),
            ("::ffff:169.254.169.254", AddressClass::Metadata),
            ("64:ff9b::a9fe:a9fe", AddressClass::Metadata),
            ("224.0.0.1", AddressClass::Multicast),
            ("ff02::1", AddressClass::Multicast),
            ("255.255.255.255", AddressClass::Broadcast),
            ("0.0.0.0", AddressClass::Unspecified),
            ("::", AddressClass::Unspecified),
        ] {
            for host in [None, Some("hooks.internal.example")] {
                assert_eq!(
                    open.check_address(ip(text), host),
                    Err(PolicyViolation::Address(class)),
                    "{text} via {host:?}"
                );
            }
        }
        assert_eq!(
            open.check_url(&url("https://169.254.169.254/latest/meta-data/")),
            Err(PolicyViolation::Address(AddressClass::Metadata))
        );
    }

    #[test]
    fn every_notation_of_an_ipv4_address_is_judged_like_the_address() {
        // Every first octet with tails that hit the special ranges inside it: the integer, hexadecimal and octal
        // URL notations, and the mapped, compatible, NAT64 and 6to4 IPv6 forms, must never be judged more leniently
        // than the dotted address (a bypass of the policy by spelling).
        let policy = policy();
        let tails: [[u8; 3]; 6] = [
            [0, 0, 1],
            [16, 0, 1],
            [168, 1, 1],
            [254, 169, 254],
            [0, 2, 1],
            [255, 255, 255],
        ];
        for a in 0..=255_u8 {
            for [b, c, d] in tails {
                let v4 = Ipv4Addr::new(a, b, c, d);
                let dotted = policy.check_url(&url(&format!("https://{v4}/")));
                let number = u32::from(v4);
                for spelled in [
                    format!("https://{number}/"),
                    format!("https://{number:#x}/"),
                    format!("https://0{number:o}/"),
                    format!("https://{a:#x}.{b}.{c}.{d}/"),
                ] {
                    assert_eq!(policy.check_url(&url(&spelled)), dotted, "{spelled} vs {v4}");
                }
                let [h1, h2] = [u16::from_be_bytes([a, b]), u16::from_be_bytes([c, d])];
                let v4_class = classify(IpAddr::V4(v4));
                let translated = [
                    Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, h1, h2),
                    Ipv6Addr::new(0x2002, h1, h2, 0, 0, 0, 0, 1),
                ];
                for v6 in translated {
                    assert_eq!(classify(IpAddr::V6(v6)), v4_class, "{v6} routes to {v4}");
                }
                let mapped = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, h1, h2);
                assert_eq!(
                    classify(IpAddr::V6(mapped)),
                    Some(v4_class.unwrap_or(AddressClass::Reserved)),
                    "{mapped} stands for {v4}"
                );
                assert!(
                    policy.check_address(IpAddr::V6(mapped), None).is_err(),
                    "a mapped address is never a destination: {mapped}"
                );
            }
        }
    }
}
