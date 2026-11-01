//! ETags of versioned management API resources.
//!
//! Mutable API resources (tenants, principals, calendars, grants, webhooks) carry a `version` counter that the
//! store bumps on every write. The API exposes it as the `ETag` header (`"v7"`) and accepts it in `If-Match`, so
//! a stale write answers 412 (PLAN 2.10). Calendar objects have content ETags instead (`domain::ETag`).

/// The strong ETag of a resource at `version`: `"v{version}"` including the quotes.
pub fn etag_for_version(version: i64) -> String {
    format!("\"v{version}\"")
}

/// Reads the version out of an ETag produced by [`etag_for_version`]. Weak validators (`W/"v7"`), other tags and
/// non-positive versions are not understood and yield `None`.
pub fn version_from_etag(etag: &str) -> Option<i64> {
    let digits = etag.trim().strip_prefix("\"v")?.strip_suffix('"')?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) || (digits.len() > 1 && digits.starts_with('0'))
    {
        return None;
    }
    digits.parse::<i64>().ok().filter(|version| *version > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_round_trip_through_etags() {
        for version in [1, 2, 10, 99_999, i64::MAX] {
            assert_eq!(version_from_etag(&etag_for_version(version)), Some(version));
        }
        assert_eq!(etag_for_version(7), "\"v7\"");
    }

    #[test]
    fn foreign_and_malformed_etags_are_not_versions() {
        for bad in [
            "",
            "v7",
            "\"7\"",
            "W/\"v7\"",
            "\"v\"",
            "\"v0\"",
            "\"v-3\"",
            "\"v07\"",
            "\"v9223372036854775808\"",
            "\"vx\"",
            "\"abcdefghijklmnopqrstuv\"",
        ] {
            assert_eq!(version_from_etag(bad), None, "{bad:?}");
        }
        assert_eq!(version_from_etag("  \"v3\"  "), Some(3));
    }
}
