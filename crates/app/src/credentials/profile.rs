//! Client configuration documents: the Apple configuration profile and the DAVx5 login URI.
//!
//! Both contain a freshly minted app password, so the responses are `no-store` and never logged. The profile
//! identifiers are stable per principal (`{prefix}.caldav.{principal id}`), so installing a profile again replaces
//! the one on the device instead of adding a second account.

use core::fmt::Write as _;

use davhaven_domain::PrincipalId;
use url::Url;
use uuid::Uuid;

/// Everything a configuration profile contains.
pub(super) struct Profile<'a> {
    /// The reverse-DNS prefix of the payload identifiers.
    pub(super) identifier_prefix: &'a str,
    /// The organization shown on the device.
    pub(super) organization: &'a str,
    /// The principal the profile is for.
    pub(super) principal: PrincipalId,
    /// The name of the account on the device.
    pub(super) account_name: &'a str,
    /// The server (`dav` base URL).
    pub(super) server: &'a Url,
    /// The path of the principal resource.
    pub(super) principal_path: &'a str,
    /// The login name.
    pub(super) username: &'a str,
    /// The app password.
    pub(super) password: &'a str,
    /// The subscription feed to add, when the profile includes one.
    pub(super) feed: Option<&'a Url>,
}

/// Escapes text for a plist `<string>`.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn string(key: &str, value: &str) -> String {
    format!("<key>{key}</key><string>{}</string>", escape(value))
}

/// A deterministic payload UUID: the same identifier and role always give the same UUID.
fn payload_uuid(identifier: &str, role: &str) -> Uuid {
    Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("davhaven:profile:{identifier}:{role}").as_bytes(),
    )
}

/// The reverse-DNS prefix of profile identifiers when the tenant configured none: the host of the server, reversed
/// (`cal.example.org` becomes `org.example.cal`).
pub(super) fn default_prefix(server: &Url) -> String {
    let host = server.host_str().unwrap_or("calendar");
    let labels: Vec<&str> = host.split('.').rev().collect();
    labels.join(".")
}

const PLIST_HEAD: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
    <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n";

/// The Apple configuration profile (`application/x-apple-aspen-config`) of a principal.
pub(super) fn mobileconfig(profile: &Profile<'_>) -> String {
    let identifier = format!("{}.caldav.{}", profile.identifier_prefix, profile.principal);
    let port = profile.server.port_or_known_default().unwrap_or(443);
    let ssl = profile.server.scheme() == "https";
    let uuid = |role: &str| payload_uuid(&identifier, role).to_string();
    let mut payloads = String::new();
    payloads.push_str("<dict>");
    payloads.push_str(&string("CalDAVAccountDescription", profile.account_name));
    payloads.push_str(&string("CalDAVHostName", profile.server.host_str().unwrap_or_default()));
    let _ = write!(payloads, "<key>CalDAVPort</key><integer>{port}</integer>");
    payloads.push_str(&string("CalDAVPrincipalURL", profile.principal_path));
    payloads.push_str(&string("CalDAVUsername", profile.username));
    payloads.push_str(&string("CalDAVPassword", profile.password));
    let _ = write!(payloads, "<key>CalDAVUseSSL</key><{ssl}/>");
    payloads.push_str(&string("PayloadDescription", "Configures a CalDAV account"));
    payloads.push_str(&string("PayloadDisplayName", profile.account_name));
    payloads.push_str(&string("PayloadIdentifier", &format!("{identifier}.account")));
    payloads.push_str(&string("PayloadType", "com.apple.caldav.account"));
    payloads.push_str(&string("PayloadUUID", &uuid("account")));
    payloads.push_str("<key>PayloadVersion</key><integer>1</integer></dict>");
    if let Some(feed) = profile.feed {
        payloads.push_str("<dict>");
        payloads.push_str(&string("SubCalAccountDescription", profile.account_name));
        payloads.push_str(&string("SubCalAccountHostName", feed.host_str().unwrap_or_default()));
        payloads.push_str(&string("SubCalAccountURL", feed.as_str()));
        payloads.push_str(&string("PayloadIdentifier", &format!("{identifier}.feed")));
        payloads.push_str(&string("PayloadType", "com.apple.subscribedcalendar.account"));
        payloads.push_str(&string("PayloadUUID", &uuid("feed")));
        payloads.push_str("<key>PayloadVersion</key><integer>1</integer></dict>");
    }
    let mut document = String::from(PLIST_HEAD);
    document.push_str("<plist version=\"1.0\"><dict><key>PayloadContent</key><array>");
    document.push_str(&payloads);
    document.push_str("</array>");
    document.push_str(&string("PayloadDisplayName", profile.account_name));
    document.push_str(&string("PayloadIdentifier", &identifier));
    document.push_str(&string("PayloadOrganization", profile.organization));
    document.push_str(&string("PayloadType", "Configuration"));
    document.push_str(&string("PayloadUUID", &uuid("profile")));
    document.push_str("<key>PayloadRemovalDisallowed</key><false/><key>PayloadVersion</key><integer>1</integer>");
    document.push_str("</dict></plist>\n");
    document
}

/// The DAVx5 login URI for a QR code: `davx5://{user}:{password}@{host}/dav/`.
///
/// Returns `None` when the server URL cannot carry credentials.
pub(super) fn davx5_uri(server: &Url, username: &str, password: &str) -> Option<String> {
    let host = server.host_str()?;
    let mut uri = Url::parse(&format!("davx5://placeholder@{host}/dav/")).ok()?;
    uri.set_username(username).ok()?;
    uri.set_password(Some(password)).ok()?;
    if let Some(port) = server.port() {
        uri.set_port(Some(port)).ok()?;
    }
    Some(uri.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> Url {
        Url::parse("https://cal.example.org/").unwrap()
    }

    #[test]
    fn the_default_prefix_is_the_reversed_host() {
        assert_eq!(default_prefix(&server()), "org.example.cal");
        assert_eq!(
            default_prefix(&Url::parse("http://localhost:8080/").unwrap()),
            "localhost"
        );
    }

    #[test]
    fn the_profile_has_stable_identifiers_and_carries_the_login() {
        let principal = PrincipalId::from_uuid(Uuid::from_u128(9));
        let server = server();
        let feed = Url::parse("https://cal.example.org/feeds/dvh_feed_x.ics").unwrap();
        let build = |feed: Option<&Url>| {
            mobileconfig(&Profile {
                identifier_prefix: "org.example",
                organization: "Example & Co",
                principal,
                account_name: "Calendar <work>",
                server: &server,
                principal_path: "/dav/principals/acme/anna/",
                username: "anna@acme.example",
                password: "abcd-efgh-ijkl-mnop-qrst-uvwx-yz23-abcd-efgh",
                feed,
            })
        };
        let profile = build(Some(&feed));
        for expected in [
            "org.example.caldav.00000000-0000-0000-0000-000000000009",
            "<key>CalDAVHostName</key><string>cal.example.org</string>",
            "<key>CalDAVPort</key><integer>443</integer>",
            "<key>CalDAVUseSSL</key><true/>",
            "<string>/dav/principals/acme/anna/</string>",
            "<string>anna@acme.example</string>",
            "<string>abcd-efgh-ijkl-mnop-qrst-uvwx-yz23-abcd-efgh</string>",
            "com.apple.caldav.account",
            "com.apple.subscribedcalendar.account",
            "Example &amp; Co",
            "Calendar &lt;work&gt;",
        ] {
            assert!(profile.contains(expected), "{expected}\n{profile}");
        }
        assert_eq!(profile, build(Some(&feed)), "the same input gives the same document");
        assert!(!build(None).contains("subscribedcalendar"));
    }

    #[test]
    fn the_davx5_uri_encodes_the_login() {
        let uri = davx5_uri(&server(), "anna@acme.example", "abcd-efgh").unwrap();
        assert_eq!(uri, "davx5://anna%40acme.example:abcd-efgh@cal.example.org/dav/");
        let with_port = davx5_uri(&Url::parse("https://cal.example.org:8443/").unwrap(), "anna", "secret").unwrap();
        assert!(with_port.contains("@cal.example.org:8443/dav/"), "{with_port}");
    }
}
