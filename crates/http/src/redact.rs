//! Redaction of tokens in paths, headers and logs.
//!
//! Credentials travel in headers (`Authorization`) and, for feeds, RSVP links and OAuth callbacks, in URLs
//! (PLAN 2.6, R8). Nothing of that may reach a log line, a span or a metric label:
//!
//! * the tracing layer labels with the route **template** and never records the raw path or query;
//! * [`redact_path`] masks token segments for the places that must show a path anyway (error reports, captures);
//! * [`sensitive_headers`] is the list of headers the edge marks as sensitive, so that `Debug` output of a request
//!   hides their values.

use std::borrow::Cow;

use axum::http::HeaderName;
use axum::http::header::{AUTHORIZATION, COOKIE, PROXY_AUTHORIZATION, SET_COOKIE};

/// What replaces the secret part of a token.
pub const REDACTED: &str = "<redacted>";

/// The prefixes of the typed credential formats (PLAN 2.6): API tokens, feed tokens and RSVP tokens.
const TOKEN_PREFIXES: [&str; 3] = ["dvh_pat_", "dvh_feed_", "dvh_rsvp_"];

/// The first path segments whose next segment is always a secret, whatever it looks like.
const SECRET_PARENTS: [&str; 2] = ["feeds", "rsvp"];

/// The headers whose values are credentials.
pub fn sensitive_headers() -> Vec<HeaderName> {
    vec![AUTHORIZATION, PROXY_AUTHORIZATION, COOKIE, SET_COOKIE]
}

/// Masks one path segment that is a credential, keeping the credential type and a file extension.
fn redact_segment(segment: &str, after_secret_parent: bool) -> Option<String> {
    let (stem, extension) = match segment.rsplit_once('.') {
        Some((stem, extension)) => (stem, Some(extension)),
        None => (segment, None),
    };
    let typed = TOKEN_PREFIXES.iter().find(|prefix| stem.starts_with(**prefix));
    let head = match typed {
        Some(prefix) => (*prefix).to_owned(),
        None if after_secret_parent => String::new(),
        None => return None,
    };
    Some(match extension {
        Some(extension) => format!("{head}{REDACTED}.{extension}"),
        None => format!("{head}{REDACTED}"),
    })
}

/// The path with every credential masked: segments that start with a typed token prefix keep only the prefix, and
/// the segment after `/feeds/` and `/rsvp/` is masked entirely (a file extension is kept). Paths without
/// credentials are returned unchanged and without allocating.
pub fn redact_path(path: &str) -> Cow<'_, str> {
    let mut out = String::with_capacity(path.len());
    let mut changed = false;
    let mut previous_is_parent = false;
    for (index, segment) in path.split('/').enumerate() {
        if index > 0 {
            out.push('/');
        }
        match redact_segment(segment, previous_is_parent) {
            Some(masked) if !segment.is_empty() => {
                out.push_str(&masked);
                changed = true;
            }
            _ => out.push_str(segment),
        }
        previous_is_parent = SECRET_PARENTS.contains(&segment);
    }
    if changed { Cow::Owned(out) } else { Cow::Borrowed(path) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feed_and_rsvp_tokens_are_masked_in_paths() {
        let cases = [
            (
                "/feeds/dvh_feed_abcdefghijkl_SECRETSECRETSECRETSECRETSECRETSECRETSEC.ics",
                "/feeds/dvh_feed_<redacted>.ics",
            ),
            ("/rsvp/dvh_rsvp_abcdefghijkl_SECRET", "/rsvp/dvh_rsvp_<redacted>"),
            ("/feeds/anything-at-all.ics", "/feeds/<redacted>.ics"),
            ("/rsvp/whatever", "/rsvp/<redacted>"),
            ("/x/dvh_pat_abcdefghijkl_SECRET/y", "/x/dvh_pat_<redacted>/y"),
        ];
        for (path, expected) in cases {
            assert_eq!(redact_path(path), expected, "{path}");
        }
    }

    #[test]
    fn paths_without_credentials_pass_through_borrowed() {
        for path in [
            "/",
            "/dav/calendars/acme/anna/work/event.ics",
            "/api/v1/tenants/acme/principals",
            "/feeds",
            "/feeds/",
            "/oauth/google/callback",
            "/assets/theme/logo.svg",
        ] {
            assert!(matches!(redact_path(path), Cow::Borrowed(_)), "{path}");
        }
    }

    #[test]
    fn no_secret_survives_redaction() {
        let secret = "ZZZSECRETZZZ";
        for path in [
            format!("/feeds/dvh_feed_abc_{secret}.ics"),
            format!("/rsvp/{secret}"),
            format!("/feeds/{secret}"),
            format!("/a/dvh_rsvp_x_{secret}/b/dvh_pat_y_{secret}"),
        ] {
            let masked = redact_path(&path);
            assert!(!masked.contains(secret), "{path} -> {masked}");
        }
    }

    #[test]
    fn credential_headers_are_listed() {
        let names: Vec<String> = sensitive_headers()
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect();
        assert_eq!(
            names,
            vec!["authorization", "proxy-authorization", "cookie", "set-cookie"]
        );
    }
}
