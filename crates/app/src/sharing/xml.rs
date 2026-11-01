//! The XML of CalendarServer notifications (`CS:invite-notification` and `CS:invite-reply`).
//!
//! The notification collection of a principal holds these documents; clients read them, show the invitation and
//! delete the resource afterwards. The bodies are produced here, once, when the notification is created.

use chrono::{DateTime, Utc};
use davhaven_domain::{CalendarUserAddress, ComponentKind, GrantAccess};

const HEAD: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CS:notification xmlns:D=\"DAV:\" \
    xmlns:C=\"urn:ietf:params:xml:ns:caldav\" xmlns:CS=\"http://calendarserver.org/ns/\">\n";

/// Escapes text for element content and attribute values.
pub(super) fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c if c.is_control() && !matches!(c, '\n' | '\t') => {}
            c => out.push(c),
        }
    }
    out
}

fn stamp(at: DateTime<Utc>) -> String {
    at.format("%Y%m%dT%H%M%SZ").to_string()
}

fn element(name: &str, text: &str) -> String {
    format!("<{name}>{}</{name}>", escape(text))
}

/// What an invitation tells the sharee.
pub(super) struct Invitation<'a> {
    pub(super) at: DateTime<Utc>,
    pub(super) invite_uid: &'a str,
    pub(super) sharee: &'a CalendarUserAddress,
    pub(super) access: GrantAccess,
    pub(super) host_href: &'a str,
    pub(super) organizer: &'a CalendarUserAddress,
    pub(super) organizer_name: &'a str,
    pub(super) summary: Option<&'a str>,
    pub(super) components: &'a [ComponentKind],
}

/// The body of a `CS:invite-notification`.
pub(super) fn invite(invitation: &Invitation<'_>) -> String {
    let access = match invitation.access {
        GrantAccess::Read => "<CS:read/>",
        GrantAccess::ReadWrite | GrantAccess::Admin => "<CS:read-write/>",
    };
    let components = invitation
        .components
        .iter()
        .map(|component| format!("<C:comp name=\"{}\"/>", component.as_ical()))
        .collect::<Vec<String>>()
        .concat();
    let mut lines: Vec<String> = vec![
        format!("  {}", element("CS:dtstamp", &stamp(invitation.at))),
        "  <CS:invite-notification>".to_owned(),
        format!("    {}", element("CS:uid", invitation.invite_uid)),
        format!("    <D:href>{}</D:href>", escape(invitation.sharee.as_str())),
        "    <CS:invite-noresponse/>".to_owned(),
        format!("    <CS:access>{access}</CS:access>"),
        format!(
            "    <CS:hosturl><D:href>{}</D:href></CS:hosturl>",
            escape(invitation.host_href)
        ),
        format!(
            "    <CS:organizer><D:href>{}</D:href>{}</CS:organizer>",
            escape(invitation.organizer.as_str()),
            element("CS:common-name", invitation.organizer_name)
        ),
    ];
    if let Some(summary) = invitation.summary {
        lines.push(format!("    {}", element("CS:summary", summary)));
    }
    lines.push(format!(
        "    <CS:supported-calendar-component-set>{components}</CS:supported-calendar-component-set>"
    ));
    lines.push("  </CS:invite-notification>".to_owned());
    document(&lines)
}

/// The XML declaration, the root element and the lines of a notification.
fn document(lines: &[String]) -> String {
    let mut body = String::from(HEAD);
    body.push_str(&lines.join("\n"));
    body.push_str("\n</CS:notification>\n");
    body
}

/// What a reply tells the owner.
pub(super) struct Reply<'a> {
    pub(super) at: DateTime<Utc>,
    pub(super) accepted: bool,
    pub(super) sharee: &'a CalendarUserAddress,
    pub(super) sharee_name: &'a str,
    pub(super) host_href: &'a str,
    pub(super) in_reply_to: &'a str,
    pub(super) summary: Option<&'a str>,
}

/// The body of a `CS:invite-reply` notification.
pub(super) fn reply(reply: &Reply<'_>) -> String {
    let answer = if reply.accepted {
        "<CS:invite-accepted/>"
    } else {
        "<CS:invite-declined/>"
    };
    let mut lines: Vec<String> = vec![
        format!("  {}", element("CS:dtstamp", &stamp(reply.at))),
        "  <CS:invite-reply>".to_owned(),
        format!("    <D:href>{}</D:href>", escape(reply.sharee.as_str())),
        format!("    {answer}"),
        format!(
            "    <CS:hosturl><D:href>{}</D:href></CS:hosturl>",
            escape(reply.host_href)
        ),
        format!("    {}", element("CS:in-reply-to", reply.in_reply_to)),
    ];
    if let Some(summary) = reply.summary {
        lines.push(format!("    {}", element("CS:summary", summary)));
    }
    lines.push(format!("    {}", element("CS:common-name", reply.sharee_name)));
    lines.push("  </CS:invite-reply>".to_owned());
    document(&lines)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn address(text: &str) -> CalendarUserAddress {
        CalendarUserAddress::parse(text).unwrap()
    }

    #[test]
    fn text_is_escaped_and_control_characters_are_dropped() {
        assert_eq!(escape("a & b <c> \"d\"\u{7}"), "a &amp; b &lt;c&gt; &quot;d&quot;");
    }

    #[test]
    fn an_invitation_names_everything_a_client_shows() {
        let at = Utc.with_ymd_and_hms(2027, 1, 2, 3, 4, 5).unwrap();
        let sharee = address("mailto:rita@acme.example");
        let organizer = address("mailto:olivia@acme.example");
        let xml = invite(&Invitation {
            at,
            invite_uid: "uid-1",
            sharee: &sharee,
            access: GrantAccess::ReadWrite,
            host_href: "/dav/calendars/acme/olivia/projects/",
            organizer: &organizer,
            organizer_name: "Olivia <Owner>",
            summary: Some("Projects & plans"),
            components: &[ComponentKind::Event, ComponentKind::Todo],
        });
        for expected in [
            "<CS:dtstamp>20270102T030405Z</CS:dtstamp>",
            "<CS:uid>uid-1</CS:uid>",
            "<D:href>mailto:rita@acme.example</D:href>",
            "<CS:invite-noresponse/>",
            "<CS:access><CS:read-write/></CS:access>",
            "<CS:hosturl><D:href>/dav/calendars/acme/olivia/projects/</D:href></CS:hosturl>",
            "<CS:common-name>Olivia &lt;Owner&gt;</CS:common-name>",
            "<CS:summary>Projects &amp; plans</CS:summary>",
            "<C:comp name=\"VEVENT\"/><C:comp name=\"VTODO\"/>",
        ] {
            assert!(xml.contains(expected), "{expected}\n{xml}");
        }
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    }

    /// A file of `testdata/dav/sharing`, the documents the DAV crate is tested with.
    fn fixture(name: &str) -> String {
        davhaven_fixtures::dav::sharing(name).unwrap_or_else(|error| panic!("{name}: {error}"))
    }

    #[test]
    fn the_notifications_are_the_documents_the_dav_layer_is_tested_with() {
        // The DAV crate serves these documents as they are stored and reads them in its unit tests and protocol
        // tests (`testdata/dav/sharing`). They are what this module writes, so that a change of either is a visible
        // change of a file.
        let sharee = address("mailto:ben@acme.example");
        let organizer = address("mailto:anna@acme.example");
        let invitation = invite(&Invitation {
            at: Utc.with_ymd_and_hms(2027, 1, 1, 0, 3, 0).unwrap(),
            invite_uid: "7b2c4f10-4d2e-4f55-9a3e-0d3b2a6c1e11",
            sharee: &sharee,
            access: GrantAccess::ReadWrite,
            host_href: "/dav/calendars/acme/anna/work/",
            organizer: &organizer,
            organizer_name: "Anna Acme",
            summary: Some("Work"),
            components: &[ComponentKind::Event, ComponentKind::Todo],
        });
        assert_eq!(invitation, fixture("notification-invite.xml"));
        let answer = reply(&Reply {
            at: Utc.with_ymd_and_hms(2027, 1, 1, 0, 5, 0).unwrap(),
            accepted: true,
            sharee: &sharee,
            sharee_name: "Ben Baker",
            host_href: "/dav/calendars/acme/anna/work/",
            in_reply_to: "7b2c4f10-4d2e-4f55-9a3e-0d3b2a6c1e11",
            summary: None,
        });
        assert_eq!(answer, fixture("notification-invite-reply.xml"));
    }

    #[test]
    fn a_reply_tells_the_owner_what_the_sharee_answered() {
        let at = Utc.with_ymd_and_hms(2027, 1, 2, 3, 4, 5).unwrap();
        let sharee = address("mailto:rita@acme.example");
        for (accepted, element) in [(true, "<CS:invite-accepted/>"), (false, "<CS:invite-declined/>")] {
            let xml = reply(&Reply {
                at,
                accepted,
                sharee: &sharee,
                sharee_name: "Rita",
                host_href: "/dav/calendars/acme/olivia/projects/",
                in_reply_to: "uid-1",
                summary: None,
            });
            assert!(xml.contains(element), "{xml}");
            assert!(xml.contains("<CS:in-reply-to>uid-1</CS:in-reply-to>"), "{xml}");
            assert!(!xml.contains("CS:summary"), "{xml}");
        }
    }
}
