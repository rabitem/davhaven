//! Tenant resolution from paths and login domains.
//!
//! Most requests name their tenant in the URL (PLAN 2.5): `/api/v1/tenants/{tenant}/…` for the management API and
//! `/dav/principals/{tenant}/…` and `/dav/calendars/{tenant}/…` for DAV. The edge extracts that slug as the
//! *tenant hint* of the authentication request; the `AuthService` then makes sure the credential belongs to that
//! tenant (a valid credential for another tenant is authenticated, and the request fails with `NotFound`, like
//! every resource the caller cannot see) and resolves system tokens and bare logins against it. The other way to
//! name a tenant, the login domain of `name@login_domain`, is resolved by the `AuthService` from the Basic
//! credentials, so the edge only deals with paths.
//!
//! A segment that is not a valid tenant slug yields no hint; the request then fails later, on its own terms, with
//! the 404 of the resource that cannot exist.

use davhaven_domain::TenantSlug;
use percent_encoding::percent_decode_str;

use crate::surface::Surface;

/// The prefix of the management API in the URL space.
const API_PREFIX: [&str; 3] = ["api", "v1", "tenants"];

/// The tenant slug a request path names, if its surface puts one in the path.
///
/// `path` is the raw (percent-encoded) path of the request URI. The web and MCP surfaces never name a tenant in
/// the path: their credentials carry it.
pub fn tenant_hint(surface: Surface, path: &str) -> Option<TenantSlug> {
    let mut segments = path.split('/').skip(1);
    let segment = match surface {
        Surface::Api => {
            for expected in API_PREFIX {
                if segments.next()? != expected {
                    return None;
                }
            }
            segments.next()?
        }
        Surface::Dav => {
            if segments.next()? != "dav" || !matches!(segments.next()?, "principals" | "calendars") {
                return None;
            }
            segments.next()?
        }
        Surface::Web | Surface::Mcp => return None,
    };
    let decoded = percent_decode_str(segment).decode_utf8().ok()?;
    TenantSlug::parse(&decoded).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hint(surface: Surface, path: &str) -> Option<String> {
        tenant_hint(surface, path).map(|slug| slug.as_str().to_owned())
    }

    #[test]
    fn api_paths_name_the_tenant_after_the_tenants_collection() {
        let cases = [
            ("/api/v1/tenants/acme", Some("acme")),
            ("/api/v1/tenants/acme/", Some("acme")),
            ("/api/v1/tenants/acme/principals/anna/calendars", Some("acme")),
            ("/api/v1/tenants/ac%6De", Some("acme")),
            ("/api/v1/tenants", None),
            ("/api/v1/tenants/", None),
            ("/api/v1/other/acme", None),
            ("/api/v2/tenants/acme", None),
            ("/tenants/acme", None),
            ("/api/v1/tenants/Not%20Valid", None),
            ("/api/v1/tenants/%FF", None),
            ("", None),
        ];
        for (path, expected) in cases {
            assert_eq!(hint(Surface::Api, path).as_deref(), expected, "{path}");
        }
    }

    #[test]
    fn dav_paths_name_the_tenant_in_principals_and_calendars() {
        let cases = [
            ("/dav/principals/acme/anna/", Some("acme")),
            ("/dav/calendars/globex/gina/work/event.ics", Some("globex")),
            ("/dav/calendars/globex", Some("globex")),
            ("/dav/", None),
            ("/dav", None),
            ("/dav/other/acme/anna/", None),
            ("/.well-known/caldav", None),
            ("/dav/calendars/UPPER/anna/", None),
        ];
        for (path, expected) in cases {
            assert_eq!(hint(Surface::Dav, path).as_deref(), expected, "{path}");
        }
    }

    #[test]
    fn web_and_mcp_credentials_carry_their_tenant() {
        for surface in [Surface::Web, Surface::Mcp] {
            assert_eq!(hint(surface, "/api/v1/tenants/acme"), None);
            assert_eq!(hint(surface, "/mcp"), None);
        }
    }
}
