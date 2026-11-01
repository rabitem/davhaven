//! `PublicUrls`: absolute URLs derived from configuration, never from request headers.
//!
//! Mails, feeds, client configuration and OAuth redirects need absolute URLs. They are built from the configured
//! public base URL (`server.public_base_url`) and the per-tenant overrides in the tenant settings, so a forged
//! `Host` header can never end up in a link. DAV responses use path-absolute hrefs from
//! [`ResourcePath::format`]; this type turns them into absolute URLs where needed.
//!
//! Base URLs must be bare origins (`https://cal.example.org` or with a port): the router paths (`/dav/...`,
//! `/feeds/...`) start at the root, so a path prefix is not supported.

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use url::Url;

use crate::path::ResourcePath;
use crate::settings::TenantSettings;

/// Characters that stay literal when a token or provider name becomes a path segment.
const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

/// Error for a base URL that cannot be used to build links.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid base URL: {0}")]
pub struct UrlError(&'static str);

impl UrlError {
    /// The rule that was violated.
    pub const fn reason(&self) -> &'static str {
        self.0
    }
}

/// Checks that `url` is a bare http(s) origin without credentials, query or fragment.
pub(crate) fn validate_base_url(url: &Url) -> Result<(), &'static str> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err("must use http or https");
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err("must have a host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("must not contain credentials");
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("must not contain a query or fragment");
    }
    if url.path() != "/" {
        return Err("must not contain a path prefix");
    }
    Ok(())
}

/// Builds absolute URLs from the configured base URLs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicUrls {
    public: Url,
    dav: Url,
}

impl PublicUrls {
    /// Creates the URL builder for one public base URL; DAV lives under the same origin.
    ///
    /// # Errors
    ///
    /// Returns [`UrlError`] unless the URL is a bare http(s) origin.
    pub fn new(public_base: Url) -> Result<Self, UrlError> {
        validate_base_url(&public_base).map_err(UrlError)?;
        Ok(Self {
            dav: public_base.clone(),
            public: public_base,
        })
    }

    /// Uses a different origin for DAV links (`dav_base_url`).
    ///
    /// # Errors
    ///
    /// Returns [`UrlError`] unless the URL is a bare http(s) origin.
    pub fn with_dav_base(mut self, dav_base: Url) -> Result<Self, UrlError> {
        validate_base_url(&dav_base).map_err(UrlError)?;
        self.dav = dav_base;
        Ok(self)
    }

    /// The URLs of one tenant: the tenant's `public_base_url` and `dav_base_url` override the server-wide ones.
    /// An override that fails validation is ignored (settings are validated when written).
    #[must_use]
    pub fn for_tenant(&self, settings: &TenantSettings) -> Self {
        let mut urls = self.clone();
        if let Some(public) = settings
            .public_base_url
            .as_ref()
            .filter(|url| validate_base_url(url).is_ok())
        {
            urls.public = public.clone();
            if settings.dav_base_url.is_none() {
                urls.dav = public.clone();
            }
        }
        if let Some(dav) = settings
            .dav_base_url
            .as_ref()
            .filter(|url| validate_base_url(url).is_ok())
        {
            urls.dav = dav.clone();
        }
        urls
    }

    /// The public base URL (with a trailing slash path).
    pub fn public_base(&self) -> &Url {
        &self.public
    }

    /// The DAV base URL (with a trailing slash path).
    pub fn dav_base(&self) -> &Url {
        &self.dav
    }

    fn join(base: &Url, path: &str) -> Url {
        // `path` always starts with a slash and is already percent-encoded, so joining cannot fail; the fallback
        // keeps the function total.
        base.join(path).unwrap_or_else(|_| base.clone())
    }

    /// `/.well-known/caldav` on the public origin.
    pub fn well_known_caldav(&self) -> Url {
        Self::join(&self.public, "/.well-known/caldav")
    }

    /// The DAV entry point, `/dav/`.
    pub fn dav_root(&self) -> Url {
        Self::join(&self.dav, "/dav/")
    }

    /// The absolute URL of a DAV resource.
    pub fn dav_url(&self, path: &ResourcePath) -> Url {
        Self::join(&self.dav, &path.format())
    }

    /// The URL of a subscription feed: `/feeds/{token}.ics`. The token is the full secret token string.
    pub fn feed_url(&self, token: &str) -> Url {
        Self::join(
            &self.public,
            &format!("/feeds/{}.ics", utf8_percent_encode(token, SEGMENT)),
        )
    }

    /// The URL of an RSVP page: `/rsvp/{token}`.
    pub fn rsvp_url(&self, token: &str) -> Url {
        Self::join(&self.public, &format!("/rsvp/{}", utf8_percent_encode(token, SEGMENT)))
    }

    /// The OAuth redirect URI of a provider: `/oauth/{provider}/callback`.
    pub fn oauth_callback_url(&self, provider: &str) -> Url {
        Self::join(
            &self.public,
            &format!("/oauth/{}/callback", utf8_percent_encode(provider, SEGMENT)),
        )
    }

    /// The URL of a theme asset: `/assets/{path}`. Slashes in `path` stay separators.
    pub fn asset_url(&self, path: &str) -> Url {
        let encoded: Vec<String> = path
            .split('/')
            .filter(|segment| !segment.is_empty() && *segment != "." && *segment != "..")
            .map(|segment| utf8_percent_encode(segment, SEGMENT).to_string())
            .collect();
        Self::join(&self.public, &format!("/assets/{}", encoded.join("/")))
    }

    /// The management API root: `/api/v1/`.
    pub fn api_root(&self) -> Url {
        Self::join(&self.public, "/api/v1/")
    }

    /// The MCP endpoint: `/mcp`.
    pub fn mcp_url(&self) -> Url {
        Self::join(&self.public, "/mcp")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{CalendarSlug, ObjectUri, PrincipalName, TenantSlug};

    fn url(text: &str) -> Url {
        Url::parse(text).unwrap()
    }

    fn urls() -> PublicUrls {
        PublicUrls::new(url("https://cal.example.org")).unwrap()
    }

    #[test]
    fn builds_the_router_urls() {
        let urls = urls();
        assert_eq!(
            urls.well_known_caldav().as_str(),
            "https://cal.example.org/.well-known/caldav"
        );
        assert_eq!(urls.dav_root().as_str(), "https://cal.example.org/dav/");
        assert_eq!(
            urls.feed_url("dvh_feed_abc_def").as_str(),
            "https://cal.example.org/feeds/dvh_feed_abc_def.ics"
        );
        assert_eq!(
            urls.rsvp_url("dvh_rsvp_abc_def").as_str(),
            "https://cal.example.org/rsvp/dvh_rsvp_abc_def"
        );
        assert_eq!(
            urls.oauth_callback_url("google").as_str(),
            "https://cal.example.org/oauth/google/callback"
        );
        assert_eq!(urls.api_root().as_str(), "https://cal.example.org/api/v1/");
        assert_eq!(urls.mcp_url().as_str(), "https://cal.example.org/mcp");
        assert_eq!(urls.public_base().as_str(), "https://cal.example.org/");
        assert_eq!(urls.dav_base().as_str(), "https://cal.example.org/");
    }

    #[test]
    fn dav_urls_use_the_canonical_encoder() {
        let path = ResourcePath::Object {
            tenant: TenantSlug::parse("acme").unwrap(),
            principal: PrincipalName::parse("anna").unwrap(),
            binding: CalendarSlug::parse("personal").unwrap(),
            object: ObjectUri::parse("meeting 1?.ics").unwrap(),
        };
        assert_eq!(
            urls().dav_url(&path).as_str(),
            "https://cal.example.org/dav/calendars/acme/anna/personal/meeting%201%3F.ics"
        );
        assert_eq!(urls().dav_url(&ResourcePath::Root), urls().dav_root());
    }

    #[test]
    fn segments_cannot_escape_their_position() {
        let urls = urls();
        assert_eq!(
            urls.feed_url("a/b?c#d").as_str(),
            "https://cal.example.org/feeds/a%2Fb%3Fc%23d.ics"
        );
        assert_eq!(urls.rsvp_url("../x").as_str(), "https://cal.example.org/rsvp/..%2Fx");
        assert_eq!(
            urls.oauth_callback_url("a/b").as_str(),
            "https://cal.example.org/oauth/a%2Fb/callback"
        );
        assert_eq!(
            urls.asset_url("css/../../app.css").as_str(),
            "https://cal.example.org/assets/css/app.css"
        );
        assert_eq!(
            urls.asset_url("img/logo mark.png").as_str(),
            "https://cal.example.org/assets/img/logo%20mark.png"
        );
    }

    #[test]
    fn base_urls_are_bare_origins() {
        for ok in [
            "https://cal.example.org",
            "https://cal.example.org/",
            "http://localhost:8080",
            "https://[::1]:9443/",
        ] {
            assert!(PublicUrls::new(url(ok)).is_ok(), "{ok}");
        }
        for (bad, reason) in [
            ("ftp://cal.example.org/", "must use http or https"),
            ("https://cal.example.org/prefix/", "must not contain a path prefix"),
            ("https://cal.example.org/?x=1", "must not contain a query or fragment"),
            ("https://cal.example.org/#top", "must not contain a query or fragment"),
            ("https://user:pw@cal.example.org/", "must not contain credentials"),
            ("https://user@cal.example.org/", "must not contain credentials"),
            ("file:///etc/passwd", "must use http or https"),
        ] {
            assert_eq!(PublicUrls::new(url(bad)).unwrap_err().reason(), reason, "{bad}");
        }
        assert_eq!(
            PublicUrls::new(url("ftp://x/")).unwrap_err().to_string(),
            "invalid base URL: must use http or https"
        );
    }

    #[test]
    fn dav_can_live_on_its_own_origin() {
        let urls = urls().with_dav_base(url("https://dav.example.org")).unwrap();
        assert_eq!(urls.dav_root().as_str(), "https://dav.example.org/dav/");
        assert_eq!(
            urls.well_known_caldav().as_str(),
            "https://cal.example.org/.well-known/caldav"
        );
        assert!(urls.clone().with_dav_base(url("https://dav.example.org/x/")).is_err());
    }

    #[test]
    fn tenants_override_the_server_urls() {
        let base = urls();
        let plain = TenantSettings::default();
        assert_eq!(base.for_tenant(&plain), base);

        let branded =
            TenantSettings::default().modified(|s| s.public_base_url = Some(url("https://calendar.acme.example")));
        let tenant = base.for_tenant(&branded);
        assert_eq!(
            tenant.feed_url("t").as_str(),
            "https://calendar.acme.example/feeds/t.ics"
        );
        assert_eq!(
            tenant.dav_root().as_str(),
            "https://calendar.acme.example/dav/",
            "DAV follows the public override"
        );

        let split = TenantSettings::default().modified(|s| {
            s.public_base_url = Some(url("https://calendar.acme.example"));
            s.dav_base_url = Some(url("https://dav.acme.example"));
        });
        let tenant = base.for_tenant(&split);
        assert_eq!(tenant.rsvp_url("t").as_str(), "https://calendar.acme.example/rsvp/t");
        assert_eq!(tenant.dav_root().as_str(), "https://dav.acme.example/dav/");

        let dav_only = TenantSettings::default().modified(|s| s.dav_base_url = Some(url("https://dav.acme.example")));
        let tenant = base.for_tenant(&dav_only);
        assert_eq!(tenant.rsvp_url("t").as_str(), "https://cal.example.org/rsvp/t");
        assert_eq!(tenant.dav_root().as_str(), "https://dav.acme.example/dav/");

        let invalid =
            TenantSettings::default().modified(|s| s.public_base_url = Some(url("https://x.example/prefix/")));
        assert_eq!(base.for_tenant(&invalid), base, "an invalid override is ignored");
    }
}
