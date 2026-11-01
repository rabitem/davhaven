//! `ResourcePath`: parsing and canonical formatting of DAV resource paths.
//!
//! The DAV namespace (PLAN 2.5) is
//!
//! ```text
//! /dav/                                                   Root
//! /dav/principals/{tenant}/{principal}/                   Principal
//! /dav/calendars/{tenant}/{principal}/                    Home
//! /dav/calendars/{tenant}/{principal}/{binding}/          Collection
//! /dav/calendars/{tenant}/{principal}/{binding}/{object}  Object
//! /dav/calendars/{tenant}/{principal}/inbox/              Inbox (items: .../inbox/{item})
//! /dav/calendars/{tenant}/{principal}/outbox/             Outbox
//! /dav/calendars/{tenant}/{principal}/notifications/      Notifications (items: .../notifications/{item})
//! ```
//!
//! [`ResourcePath::parse`] percent-decodes every segment and validates it with the natural-key types;
//! [`ResourcePath::format`] is the one canonical encoder for hrefs in DAV responses. Absolute URLs for mails,
//! feeds and client configuration come from `PublicUrls`, never from this module.

use core::fmt;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};

use crate::keys::{CalendarSlug, ObjectUri, PrincipalName, TenantSlug};

/// Characters that stay literal inside an encoded path segment: the RFC 3986 `pchar` set.
const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b'!')
    .remove(b'$')
    .remove(b'&')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')')
    .remove(b'*')
    .remove(b'+')
    .remove(b',')
    .remove(b';')
    .remove(b'=')
    .remove(b':')
    .remove(b'@');

/// Why a path could not be parsed into a [`ResourcePath`]. Every variant means "no such resource" to clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    /// The path does not start with `/dav`.
    #[error("path is outside the DAV namespace")]
    NotInNamespace,
    /// Bad percent-encoding, empty or dot segments, an encoded slash or control characters.
    #[error("path is malformed")]
    Malformed,
    /// The path has a shape that names no resource (wrong depth or unknown section).
    #[error("path does not name a resource")]
    UnknownResource,
    /// A segment is not a valid key of the named kind.
    #[error("path segment is not a valid {0}")]
    InvalidSegment(&'static str),
}

string_key!(
    /// A path-absolute, percent-encoded reference to a resource, as used in `DAV:href` elements.
    ///
    /// Starts with a single `/`, contains no whitespace or control characters and is at most 2048 bytes long.
    /// Build hrefs of resources with [`ResourcePath::href`] so that one canonical encoder is used.
    Href,
    "href",
    parse_href
);

fn parse_href(input: &str) -> Result<String, &'static str> {
    if !input.starts_with('/') || input.starts_with("//") {
        return Err("must be a path-absolute reference starting with a single slash");
    }
    if input.len() > 2048 {
        return Err("must be at most 2048 bytes");
    }
    if input.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("must not contain whitespace or control characters");
    }
    Ok(input.to_owned())
}

/// A resource in the DAV namespace.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ResourcePath {
    /// `/dav/`: the entry point of discovery.
    Root,
    /// `/dav/principals/{tenant}/{principal}/`.
    Principal {
        /// Tenant slug.
        tenant: TenantSlug,
        /// Principal name.
        principal: PrincipalName,
    },
    /// `/dav/calendars/{tenant}/{principal}/`: the calendar home listing the principal's bindings.
    Home {
        /// Tenant slug.
        tenant: TenantSlug,
        /// Principal name.
        principal: PrincipalName,
    },
    /// `/dav/calendars/{tenant}/{principal}/{binding}/`: a calendar collection through a binding.
    Collection {
        /// Tenant slug.
        tenant: TenantSlug,
        /// Principal name.
        principal: PrincipalName,
        /// Binding slug.
        binding: CalendarSlug,
    },
    /// `/dav/calendars/{tenant}/{principal}/{binding}/{object}`: a calendar object resource.
    Object {
        /// Tenant slug.
        tenant: TenantSlug,
        /// Principal name.
        principal: PrincipalName,
        /// Binding slug.
        binding: CalendarSlug,
        /// Decoded object name.
        object: ObjectUri,
    },
    /// `/dav/calendars/{tenant}/{principal}/inbox/`: the scheduling inbox.
    Inbox {
        /// Tenant slug.
        tenant: TenantSlug,
        /// Principal name.
        principal: PrincipalName,
    },
    /// `/dav/calendars/{tenant}/{principal}/outbox/`: the scheduling outbox.
    Outbox {
        /// Tenant slug.
        tenant: TenantSlug,
        /// Principal name.
        principal: PrincipalName,
    },
    /// `/dav/calendars/{tenant}/{principal}/notifications/`: the notification collection.
    Notifications {
        /// Tenant slug.
        tenant: TenantSlug,
        /// Principal name.
        principal: PrincipalName,
    },
    /// `/dav/calendars/{tenant}/{principal}/notifications/{uri}`: one notification.
    Notification {
        /// Tenant slug.
        tenant: TenantSlug,
        /// Principal name.
        principal: PrincipalName,
        /// Decoded notification name.
        uri: ObjectUri,
    },
    /// `/dav/calendars/{tenant}/{principal}/inbox/{uri}`: one scheduling inbox item.
    InboxItem {
        /// Tenant slug.
        tenant: TenantSlug,
        /// Principal name.
        principal: PrincipalName,
        /// Decoded item name.
        uri: ObjectUri,
    },
}

/// Decodes one raw path segment and rejects what can never be a resource name.
fn decode_segment(raw: &str) -> Result<String, PathError> {
    if raw.is_empty() {
        return Err(PathError::Malformed);
    }
    let decoded = percent_decode_str(raw)
        .decode_utf8()
        .map_err(|_| PathError::Malformed)?;
    if decoded == "." || decoded == ".." || decoded.contains('/') || decoded.chars().any(char::is_control) {
        return Err(PathError::Malformed);
    }
    Ok(decoded.into_owned())
}

fn tenant_segment(segment: &str) -> Result<TenantSlug, PathError> {
    TenantSlug::parse(segment).map_err(|_| PathError::InvalidSegment("tenant"))
}

fn principal_segment(segment: &str) -> Result<PrincipalName, PathError> {
    PrincipalName::parse(segment).map_err(|_| PathError::InvalidSegment("principal"))
}

fn binding_segment(segment: &str) -> Result<CalendarSlug, PathError> {
    CalendarSlug::parse(segment).map_err(|_| PathError::InvalidSegment("binding"))
}

fn object_segment(segment: &str) -> Result<ObjectUri, PathError> {
    ObjectUri::parse(segment).map_err(|_| PathError::InvalidSegment("object"))
}

fn encode_segment(segment: &str) -> String {
    utf8_percent_encode(segment, SEGMENT).to_string()
}

impl ResourcePath {
    /// Parses the path of a request URI (percent-encoded, without query or fragment).
    ///
    /// One trailing slash is accepted on every resource. `parse(format(p)) == p` holds for every path, and
    /// `format(parse(s))` is the canonical spelling of any equivalent encoding `s`.
    ///
    /// # Errors
    ///
    /// Returns a [`PathError`]; all of them answer 404 to clients.
    pub fn parse(path: &str) -> Result<Self, PathError> {
        let rest = path.strip_prefix('/').ok_or(PathError::NotInNamespace)?;
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        let first = rest.split('/').next().unwrap_or_default();
        if first != "dav" {
            return Err(PathError::NotInNamespace);
        }
        let segments = rest.split('/').map(decode_segment).collect::<Result<Vec<_>, _>>()?;
        let segments: Vec<&str> = segments.iter().map(String::as_str).collect();
        match segments.as_slice() {
            ["dav"] => Ok(Self::Root),
            ["dav", "principals", tenant, principal] => Ok(Self::Principal {
                tenant: tenant_segment(tenant)?,
                principal: principal_segment(principal)?,
            }),
            ["dav", "calendars", tenant, principal] => Ok(Self::Home {
                tenant: tenant_segment(tenant)?,
                principal: principal_segment(principal)?,
            }),
            ["dav", "calendars", tenant, principal, "inbox"] => Ok(Self::Inbox {
                tenant: tenant_segment(tenant)?,
                principal: principal_segment(principal)?,
            }),
            ["dav", "calendars", tenant, principal, "outbox"] => Ok(Self::Outbox {
                tenant: tenant_segment(tenant)?,
                principal: principal_segment(principal)?,
            }),
            ["dav", "calendars", tenant, principal, "notifications"] => Ok(Self::Notifications {
                tenant: tenant_segment(tenant)?,
                principal: principal_segment(principal)?,
            }),
            ["dav", "calendars", tenant, principal, binding] => Ok(Self::Collection {
                tenant: tenant_segment(tenant)?,
                principal: principal_segment(principal)?,
                binding: binding_segment(binding)?,
            }),
            ["dav", "calendars", tenant, principal, "inbox", uri] => Ok(Self::InboxItem {
                tenant: tenant_segment(tenant)?,
                principal: principal_segment(principal)?,
                uri: object_segment(uri)?,
            }),
            ["dav", "calendars", tenant, principal, "notifications", uri] => Ok(Self::Notification {
                tenant: tenant_segment(tenant)?,
                principal: principal_segment(principal)?,
                uri: object_segment(uri)?,
            }),
            ["dav", "calendars", _, _, "outbox", _] => Err(PathError::UnknownResource),
            ["dav", "calendars", tenant, principal, binding, object] => Ok(Self::Object {
                tenant: tenant_segment(tenant)?,
                principal: principal_segment(principal)?,
                binding: binding_segment(binding)?,
                object: object_segment(object)?,
            }),
            _ => Err(PathError::UnknownResource),
        }
    }

    /// Parses an `href` as found in request bodies and headers: a path-absolute reference or an absolute
    /// `http(s)` URL (as in the `Destination` header). Only the path is interpreted; checking the host is the
    /// caller's job.
    ///
    /// # Errors
    ///
    /// Returns a [`PathError`] when the reference is not a valid URL or does not name a resource.
    pub fn from_href(href: &str) -> Result<Self, PathError> {
        let lower = href.get(..8).unwrap_or(href).to_ascii_lowercase();
        if lower.starts_with("http://") || lower.starts_with("https://") {
            let url = url::Url::parse(href).map_err(|_| PathError::Malformed)?;
            Self::parse(url.path())
        } else {
            Self::parse(href)
        }
    }

    /// The canonical path-absolute spelling: collections end with `/`, objects and items do not.
    pub fn format(&self) -> String {
        match self {
            Self::Root => "/dav/".to_owned(),
            Self::Principal { tenant, principal } => {
                format!(
                    "/dav/principals/{}/{}/",
                    encode_segment(tenant.as_str()),
                    encode_segment(principal.as_str())
                )
            }
            Self::Home { tenant, principal } => Self::home_prefix(tenant, principal),
            Self::Collection {
                tenant,
                principal,
                binding,
            } => {
                format!(
                    "{}{}/",
                    Self::home_prefix(tenant, principal),
                    encode_segment(binding.as_str())
                )
            }
            Self::Object {
                tenant,
                principal,
                binding,
                object,
            } => format!(
                "{}{}/{}",
                Self::home_prefix(tenant, principal),
                encode_segment(binding.as_str()),
                encode_segment(object.as_str())
            ),
            Self::Inbox { tenant, principal } => format!("{}inbox/", Self::home_prefix(tenant, principal)),
            Self::Outbox { tenant, principal } => format!("{}outbox/", Self::home_prefix(tenant, principal)),
            Self::Notifications { tenant, principal } => {
                format!("{}notifications/", Self::home_prefix(tenant, principal))
            }
            Self::Notification { tenant, principal, uri } => {
                format!(
                    "{}notifications/{}",
                    Self::home_prefix(tenant, principal),
                    encode_segment(uri.as_str())
                )
            }
            Self::InboxItem { tenant, principal, uri } => {
                format!(
                    "{}inbox/{}",
                    Self::home_prefix(tenant, principal),
                    encode_segment(uri.as_str())
                )
            }
        }
    }

    fn home_prefix(tenant: &TenantSlug, principal: &PrincipalName) -> String {
        format!(
            "/dav/calendars/{}/{}/",
            encode_segment(tenant.as_str()),
            encode_segment(principal.as_str())
        )
    }

    /// The canonical spelling as an [`Href`].
    pub fn href(&self) -> Href {
        // `format` always yields a path-absolute reference without whitespace or control characters, and
        // segment limits keep it far below the href length limit.
        Href(self.format())
    }

    /// The tenant slug in the path, if the resource is below a tenant.
    pub fn tenant(&self) -> Option<&TenantSlug> {
        match self {
            Self::Root => None,
            Self::Principal { tenant, .. }
            | Self::Home { tenant, .. }
            | Self::Collection { tenant, .. }
            | Self::Object { tenant, .. }
            | Self::Inbox { tenant, .. }
            | Self::Outbox { tenant, .. }
            | Self::Notifications { tenant, .. }
            | Self::Notification { tenant, .. }
            | Self::InboxItem { tenant, .. } => Some(tenant),
        }
    }

    /// The principal name in the path, if the resource is below a principal.
    pub fn principal(&self) -> Option<&PrincipalName> {
        match self {
            Self::Root => None,
            Self::Principal { principal, .. }
            | Self::Home { principal, .. }
            | Self::Collection { principal, .. }
            | Self::Object { principal, .. }
            | Self::Inbox { principal, .. }
            | Self::Outbox { principal, .. }
            | Self::Notifications { principal, .. }
            | Self::Notification { principal, .. }
            | Self::InboxItem { principal, .. } => Some(principal),
        }
    }

    /// Whether the canonical spelling ends with a slash (the resource is a collection).
    pub const fn is_collection(&self) -> bool {
        matches!(
            self,
            Self::Root
                | Self::Principal { .. }
                | Self::Home { .. }
                | Self::Collection { .. }
                | Self::Inbox { .. }
                | Self::Outbox { .. }
                | Self::Notifications { .. }
        )
    }

    /// The containing resource: objects live in collections, collections and scheduling collections in the
    /// home, homes and principals in the root. The root has no parent.
    pub fn parent(&self) -> Option<Self> {
        match self.clone() {
            Self::Root => None,
            Self::Principal { .. } | Self::Home { .. } => Some(Self::Root),
            Self::Collection { tenant, principal, .. }
            | Self::Inbox { tenant, principal }
            | Self::Outbox { tenant, principal }
            | Self::Notifications { tenant, principal } => Some(Self::Home { tenant, principal }),
            Self::Object {
                tenant,
                principal,
                binding,
                ..
            } => Some(Self::Collection {
                tenant,
                principal,
                binding,
            }),
            Self::Notification { tenant, principal, .. } => Some(Self::Notifications { tenant, principal }),
            Self::InboxItem { tenant, principal, .. } => Some(Self::Inbox { tenant, principal }),
        }
    }

    /// The member named `name` of a collection that has named members (a calendar collection, the inbox or the
    /// notification collection); `None` for every other resource.
    pub fn child(&self, name: ObjectUri) -> Option<Self> {
        match self.clone() {
            Self::Collection {
                tenant,
                principal,
                binding,
            } => Some(Self::Object {
                tenant,
                principal,
                binding,
                object: name,
            }),
            Self::Inbox { tenant, principal } => Some(Self::InboxItem {
                tenant,
                principal,
                uri: name,
            }),
            Self::Notifications { tenant, principal } => Some(Self::Notification {
                tenant,
                principal,
                uri: name,
            }),
            _ => None,
        }
    }
}

impl fmt::Display for ResourcePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.format())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> TenantSlug {
        TenantSlug::parse(s).unwrap()
    }
    fn p(s: &str) -> PrincipalName {
        PrincipalName::parse(s).unwrap()
    }
    fn c(s: &str) -> CalendarSlug {
        CalendarSlug::parse(s).unwrap()
    }
    fn o(s: &str) -> ObjectUri {
        ObjectUri::parse(s).unwrap()
    }

    fn samples() -> Vec<ResourcePath> {
        vec![
            ResourcePath::Root,
            ResourcePath::Principal {
                tenant: t("acme"),
                principal: p("anna"),
            },
            ResourcePath::Home {
                tenant: t("acme"),
                principal: p("anna"),
            },
            ResourcePath::Collection {
                tenant: t("acme"),
                principal: p("anna"),
                binding: c("personal"),
            },
            ResourcePath::Object {
                tenant: t("acme"),
                principal: p("anna"),
                binding: c("personal"),
                object: o("e1.ics"),
            },
            ResourcePath::Inbox {
                tenant: t("acme"),
                principal: p("anna"),
            },
            ResourcePath::Outbox {
                tenant: t("acme"),
                principal: p("anna"),
            },
            ResourcePath::Notifications {
                tenant: t("acme"),
                principal: p("anna"),
            },
            ResourcePath::Notification {
                tenant: t("acme"),
                principal: p("anna"),
                uri: o("invite-1.xml"),
            },
            ResourcePath::InboxItem {
                tenant: t("acme"),
                principal: p("anna"),
                uri: o("msg 1.ics"),
            },
        ]
    }

    #[test]
    fn canonical_formats() {
        let formatted: Vec<String> = samples().iter().map(ResourcePath::format).collect();
        assert_eq!(
            formatted,
            vec![
                "/dav/",
                "/dav/principals/acme/anna/",
                "/dav/calendars/acme/anna/",
                "/dav/calendars/acme/anna/personal/",
                "/dav/calendars/acme/anna/personal/e1.ics",
                "/dav/calendars/acme/anna/inbox/",
                "/dav/calendars/acme/anna/outbox/",
                "/dav/calendars/acme/anna/notifications/",
                "/dav/calendars/acme/anna/notifications/invite-1.xml",
                "/dav/calendars/acme/anna/inbox/msg%201.ics",
            ]
        );
    }

    #[test]
    fn every_sample_round_trips() {
        for path in samples() {
            let text = path.format();
            assert_eq!(ResourcePath::parse(&text).unwrap(), path, "{text}");
            assert_eq!(path.to_string(), text);
            assert_eq!(path.href().as_str(), text);
            assert_eq!(path.is_collection(), text.ends_with('/'), "{text}");
        }
    }

    #[test]
    fn trailing_slash_is_optional_on_input() {
        let collection = ResourcePath::Collection {
            tenant: t("acme"),
            principal: p("anna"),
            binding: c("personal"),
        };
        assert_eq!(
            ResourcePath::parse("/dav/calendars/acme/anna/personal").unwrap(),
            collection
        );
        assert_eq!(
            ResourcePath::parse("/dav/calendars/acme/anna/personal/").unwrap(),
            collection
        );
        assert_eq!(ResourcePath::parse("/dav").unwrap(), ResourcePath::Root);
        let object = ResourcePath::Object {
            tenant: t("acme"),
            principal: p("anna"),
            binding: c("personal"),
            object: o("e1.ics"),
        };
        assert_eq!(
            ResourcePath::parse("/dav/calendars/acme/anna/personal/e1.ics/").unwrap(),
            object
        );
    }

    #[test]
    fn segments_are_decoded_and_re_encoded_canonically() {
        let parsed = ResourcePath::parse("/dav/calendars/acme/anna/personal/a%40b%2Bc%20d%C3%A4%25.ics").unwrap();
        let ResourcePath::Object { object, .. } = &parsed else {
            panic!("expected an object")
        };
        assert_eq!(object.as_str(), "a@b+c dä%.ics");
        assert_eq!(
            parsed.format(),
            "/dav/calendars/acme/anna/personal/a@b+c%20d%C3%A4%25.ics"
        );
        assert_eq!(ResourcePath::parse(&parsed.format()).unwrap(), parsed);
        // Reserved characters in an object name must be encoded so they cannot change the structure of the path.
        let tricky = ResourcePath::Object {
            tenant: t("acme"),
            principal: p("anna"),
            binding: c("personal"),
            object: o("a?b#c..d"),
        };
        assert!(!tricky.format().contains('?'));
        assert!(!tricky.format().contains('#'));
        assert_eq!(tricky.format(), "/dav/calendars/acme/anna/personal/a%3Fb%23c..d");
        assert_eq!(ResourcePath::parse(&tricky.format()).unwrap(), tricky);
    }

    #[test]
    fn reserved_names_resolve_to_scheduling_collections() {
        let home = |name: &str| ResourcePath::parse(&format!("/dav/calendars/acme/anna/{name}/")).unwrap();
        assert!(matches!(home("inbox"), ResourcePath::Inbox { .. }));
        assert!(matches!(home("outbox"), ResourcePath::Outbox { .. }));
        assert!(matches!(home("notifications"), ResourcePath::Notifications { .. }));
        for name in ["dropbox", ".hidden", "INBOX", "Outbox"] {
            assert!(
                matches!(
                    ResourcePath::parse(&format!("/dav/calendars/acme/anna/{name}/")),
                    Err(PathError::InvalidSegment("binding"))
                ),
                "{name}"
            );
        }
        assert_eq!(
            ResourcePath::parse("/dav/calendars/acme/anna/outbox/x"),
            Err(PathError::UnknownResource)
        );
    }

    #[test]
    fn rejections() {
        let cases: &[(&str, PathError)] = &[
            ("", PathError::NotInNamespace),
            ("/", PathError::NotInNamespace),
            ("dav/", PathError::NotInNamespace),
            ("/api/v1/tenants", PathError::NotInNamespace),
            ("/davx/", PathError::NotInNamespace),
            ("/.well-known/caldav", PathError::NotInNamespace),
            ("/dav//", PathError::Malformed),
            ("/dav/calendars//anna/", PathError::Malformed),
            ("/dav/calendars/acme/anna/%2e%2e/", PathError::Malformed),
            ("/dav/calendars/acme/anna/./", PathError::Malformed),
            ("/dav/calendars/acme/anna/personal/a%2Fb", PathError::Malformed),
            ("/dav/calendars/acme/anna/personal/a%00b", PathError::Malformed),
            ("/dav/calendars/acme/anna/personal/a%0Ab", PathError::Malformed),
            ("/dav/calendars/acme/anna/personal/%FF", PathError::Malformed),
            ("/dav/principals/", PathError::UnknownResource),
            ("/dav/principals/acme/", PathError::UnknownResource),
            ("/dav/calendars/", PathError::UnknownResource),
            ("/dav/calendars/acme/", PathError::UnknownResource),
            ("/dav/other/acme/anna/", PathError::UnknownResource),
            (
                "/dav/calendars/acme/anna/personal/e1.ics/extra",
                PathError::UnknownResource,
            ),
            ("/dav/calendars/ACME/anna/", PathError::InvalidSegment("tenant")),
            ("/dav/calendars/acme/Anna/", PathError::InvalidSegment("principal")),
            (
                "/dav/principals/acme/anna@acme/",
                PathError::InvalidSegment("principal"),
            ),
            (
                "/dav/calendars/acme/anna/bad%20slug/",
                PathError::InvalidSegment("binding"),
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(ResourcePath::parse(input), Err(*expected), "{input}");
        }
    }

    #[test]
    fn invalid_percent_escapes_stay_literal() {
        let parsed = ResourcePath::parse("/dav/calendars/acme/anna/personal/100%zz.ics").unwrap();
        let ResourcePath::Object { object, .. } = &parsed else {
            panic!("expected an object")
        };
        assert_eq!(object.as_str(), "100%zz.ics");
        assert_eq!(parsed.format(), "/dav/calendars/acme/anna/personal/100%25zz.ics");
    }

    #[test]
    fn hrefs_may_be_absolute_urls() {
        let expected = ResourcePath::parse("/dav/calendars/acme/anna/personal/e1.ics").unwrap();
        assert_eq!(
            ResourcePath::from_href("/dav/calendars/acme/anna/personal/e1.ics").unwrap(),
            expected
        );
        assert_eq!(
            ResourcePath::from_href("https://cal.example.org/dav/calendars/acme/anna/personal/e1.ics").unwrap(),
            expected
        );
        assert_eq!(
            ResourcePath::from_href("HTTP://cal.example.org:8080/dav/calendars/acme/anna/personal/e1.ics?x=1").unwrap(),
            expected
        );
        assert!(ResourcePath::from_href("https://").is_err());
        assert!(ResourcePath::from_href("ftp://cal.example.org/dav/").is_err());
        assert!(ResourcePath::from_href("").is_err());
    }

    #[test]
    fn tenant_principal_parent_and_child() {
        let object = ResourcePath::parse("/dav/calendars/acme/anna/personal/e1.ics").unwrap();
        assert_eq!(object.tenant().unwrap().as_str(), "acme");
        assert_eq!(object.principal().unwrap().as_str(), "anna");
        assert_eq!(ResourcePath::Root.tenant(), None);
        assert_eq!(ResourcePath::Root.principal(), None);

        let collection = object.parent().unwrap();
        assert_eq!(collection.format(), "/dav/calendars/acme/anna/personal/");
        assert_eq!(collection.child(o("e1.ics")).unwrap(), object);
        let home = collection.parent().unwrap();
        assert_eq!(home.format(), "/dav/calendars/acme/anna/");
        assert_eq!(home.parent().unwrap(), ResourcePath::Root);
        assert_eq!(ResourcePath::Root.parent(), None);
        assert_eq!(home.child(o("x")), None);

        let inbox = ResourcePath::parse("/dav/calendars/acme/anna/inbox/").unwrap();
        let item = inbox.child(o("m.ics")).unwrap();
        assert!(matches!(item, ResourcePath::InboxItem { .. }));
        assert_eq!(item.parent().unwrap(), inbox);
        let notifications = ResourcePath::parse("/dav/calendars/acme/anna/notifications/").unwrap();
        let notification = notifications.child(o("n.xml")).unwrap();
        assert_eq!(notification.parent().unwrap(), notifications);
        assert_eq!(
            ResourcePath::parse("/dav/principals/acme/anna/")
                .unwrap()
                .parent()
                .unwrap(),
            ResourcePath::Root
        );
    }

    #[test]
    fn every_resource_below_the_root_names_the_tenant_and_principal_of_its_path() {
        // The tenant of a path decides which tenant a request may touch; every kind of resource must report it.
        for path in samples().into_iter().skip(1) {
            let parsed = ResourcePath::parse(&path.format()).unwrap();
            assert_eq!(parsed.tenant(), Some(&t("acme")), "{path}");
            assert_eq!(parsed.principal(), Some(&p("anna")), "{path}");
        }
    }

    #[test]
    fn every_parent_of_every_sample_formats_and_parses() {
        for path in samples() {
            let mut current = Some(path);
            while let Some(path) = current {
                assert_eq!(ResourcePath::parse(&path.format()).unwrap(), path);
                current = path.parent();
            }
        }
    }

    #[test]
    fn href_validation() {
        assert!(Href::parse("/dav/calendars/acme/anna/").is_ok());
        assert!(Href::parse("/").is_ok());
        for bad in [
            "",
            "dav/",
            "//host/x",
            "/a b",
            "/a\n",
            "https://example.org/",
            &format!("/{}", "a".repeat(2048)),
        ] {
            assert!(Href::parse(bad).is_err(), "{bad:?}");
        }
    }

    mod props {
        use proptest::prelude::*;

        use super::*;

        fn tenant() -> impl Strategy<Value = TenantSlug> {
            "[a-z0-9]([a-z0-9-]{0,8}[a-z0-9])?".prop_map(|s| TenantSlug::parse(&s).unwrap())
        }

        fn principal() -> impl Strategy<Value = PrincipalName> {
            "[a-z0-9]([a-z0-9._-]{0,8}[a-z0-9])?".prop_map(|s| PrincipalName::parse(&s).unwrap())
        }

        fn binding() -> impl Strategy<Value = CalendarSlug> {
            "[A-Za-z0-9][A-Za-z0-9._-]{0,20}".prop_filter_map("reserved", |s| CalendarSlug::parse(&s).ok())
        }

        fn object() -> impl Strategy<Value = ObjectUri> {
            "[^/\\p{Cc}]{1,40}".prop_filter_map("dot segment", |s| ObjectUri::parse(&s).ok())
        }

        fn any_path() -> impl Strategy<Value = ResourcePath> {
            prop_oneof![
                Just(ResourcePath::Root),
                (tenant(), principal()).prop_map(|(tenant, principal)| ResourcePath::Principal { tenant, principal }),
                (tenant(), principal()).prop_map(|(tenant, principal)| ResourcePath::Home { tenant, principal }),
                (tenant(), principal(), binding()).prop_map(|(tenant, principal, binding)| ResourcePath::Collection {
                    tenant,
                    principal,
                    binding
                }),
                (tenant(), principal(), binding(), object()).prop_map(|(tenant, principal, binding, object)| {
                    ResourcePath::Object {
                        tenant,
                        principal,
                        binding,
                        object,
                    }
                }),
                (tenant(), principal()).prop_map(|(tenant, principal)| ResourcePath::Inbox { tenant, principal }),
                (tenant(), principal()).prop_map(|(tenant, principal)| ResourcePath::Outbox { tenant, principal }),
                (tenant(), principal())
                    .prop_map(|(tenant, principal)| ResourcePath::Notifications { tenant, principal }),
                (tenant(), principal(), object()).prop_map(|(tenant, principal, uri)| ResourcePath::Notification {
                    tenant,
                    principal,
                    uri
                }),
                (tenant(), principal(), object()).prop_map(|(tenant, principal, uri)| ResourcePath::InboxItem {
                    tenant,
                    principal,
                    uri
                }),
            ]
        }

        proptest! {
            #[test]
            fn parse_inverts_format(path in any_path()) {
                let text = path.format();
                prop_assert!(text.starts_with("/dav/"));
                prop_assert!(!text.contains(' ') && !text.contains('?') && !text.contains('#'));
                prop_assert_eq!(ResourcePath::parse(&text).unwrap(), path.clone());
                prop_assert_eq!(ResourcePath::from_href(&text).unwrap(), path);
            }

            #[test]
            fn format_is_a_fixed_point(path in any_path()) {
                let once = path.format();
                let twice = ResourcePath::parse(&once).unwrap().format();
                prop_assert_eq!(once, twice);
            }

            #[test]
            fn parsing_never_panics(input in ".{0,200}") {
                let _ = ResourcePath::parse(&input);
                let _ = ResourcePath::from_href(&input);
                let _ = ResourcePath::parse(&format!("/dav/calendars/acme/anna/{input}"));
            }
        }
    }
}
