//! Validated natural keys such as tenant slugs, principal names, object URIs, UIDs and ETags.
//!
//! Every type here is a newtype whose constructor validates (and where the plan requires it, normalizes) the
//! text, so the rest of the system can rely on the invariants: slugs and names are safe URL path segments,
//! addresses are compared case-insensitively because they are stored lowercase, and tags have the exact shape the
//! protocol layers emit.

use core::fmt;
use core::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono_tz::Tz;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ids::CalendarId;

/// Error returned when text is rejected by a natural-key constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid {kind}: {reason}")]
pub struct KeyError {
    kind: &'static str,
    reason: &'static str,
}

impl KeyError {
    /// Creates the error for the named key kind and rejected rule.
    pub(crate) const fn new(kind: &'static str, reason: &'static str) -> Self {
        Self { kind, reason }
    }

    /// The kind of key that was rejected, for example `"tenant slug"`.
    pub const fn kind(&self) -> &'static str {
        self.kind
    }

    /// The rule that was violated, as a short English phrase.
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

/// Result of a validator: the normalized text or the reason for rejection.
type Validated = Result<String, &'static str>;

/// Home slugs that never denote a calendar: scheduling and notification collections and the reserved dropbox.
const RESERVED_HOME_SLUGS: [&str; 4] = ["inbox", "outbox", "notifications", "dropbox"];

fn is_lower_alnum(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

// ---------------------------------------------------------------------------------------------------------------
// Tenant slug, principal name, calendar slug
// ---------------------------------------------------------------------------------------------------------------

fn parse_tenant_slug(input: &str) -> Validated {
    if input.is_empty() {
        return Err("must not be empty");
    }
    if input.len() > 63 {
        return Err("must be at most 63 characters");
    }
    if !input.bytes().all(|b| is_lower_alnum(b) || b == b'-') {
        return Err("may only contain lowercase letters, digits and hyphens");
    }
    if input.starts_with('-') || input.ends_with('-') {
        return Err("must start and end with a letter or digit");
    }
    Ok(input.to_owned())
}

string_key!(
    /// The immutable URL-safe identifier of a tenant (`{tenant}` in DAV and API paths).
    ///
    /// One to 63 lowercase letters, digits and hyphens; it neither starts nor ends with a hyphen.
    TenantSlug,
    "tenant slug",
    parse_tenant_slug
);

fn parse_principal_name(input: &str) -> Validated {
    if input.is_empty() {
        return Err("must not be empty");
    }
    if input.len() > 64 {
        return Err("must be at most 64 characters");
    }
    if !input
        .bytes()
        .all(|b| is_lower_alnum(b) || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err("may only contain lowercase letters, digits, dots, underscores and hyphens");
    }
    let edge_ok = |c: Option<u8>| c.is_some_and(is_lower_alnum);
    if !edge_ok(input.bytes().next()) || !edge_ok(input.bytes().next_back()) {
        return Err("must start and end with a letter or digit");
    }
    Ok(input.to_owned())
}

string_key!(
    /// The immutable login local-part of a principal (`{principal}` in DAV and API paths).
    ///
    /// One to 64 lowercase letters, digits, dots, underscores and hyphens, starting and ending with a letter or
    /// digit. Use [`PrincipalName::from_login`] to normalize the case of user-typed input.
    PrincipalName,
    "principal name",
    parse_principal_name
);

impl PrincipalName {
    /// Normalizes user-typed login text (surrounding whitespace removed, lowercased) and validates it.
    ///
    /// # Errors
    ///
    /// Returns a [`KeyError`] when the normalized text is not a valid principal name.
    pub fn from_login(input: &str) -> Result<Self, KeyError> {
        Self::parse(&input.trim().to_ascii_lowercase())
    }
}

fn parse_calendar_slug(input: &str) -> Validated {
    if input.is_empty() {
        return Err("must not be empty");
    }
    if input.len() > 100 {
        return Err("must be at most 100 characters");
    }
    if !input
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err("may only contain letters, digits, dots, underscores and hyphens");
    }
    if input.starts_with('.') {
        return Err("must not start with a dot");
    }
    if RESERVED_HOME_SLUGS
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(input))
    {
        return Err("is reserved");
    }
    Ok(input.to_owned())
}

string_key!(
    /// The immutable slug of a calendar or of a binding (the collection segment below a calendar home).
    ///
    /// One to 100 ASCII letters, digits, dots, underscores and hyphens (client-created calendars use upper case
    /// UUIDs). Names starting with a dot and the reserved home slugs `inbox`, `outbox`, `notifications` and
    /// `dropbox` (any case) are rejected, so a slug can never collide with a scheduling collection.
    CalendarSlug,
    "calendar slug",
    parse_calendar_slug
);

impl CalendarSlug {
    /// Whether `segment` is one of the reserved home slugs (`inbox`, `outbox`, `notifications`, `dropbox`).
    pub fn is_reserved(segment: &str) -> bool {
        RESERVED_HOME_SLUGS
            .iter()
            .any(|reserved| reserved.eq_ignore_ascii_case(segment))
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Object URI, external key, UID
// ---------------------------------------------------------------------------------------------------------------

fn parse_object_uri(input: &str) -> Validated {
    if input.is_empty() {
        return Err("must not be empty");
    }
    if input.len() > 255 {
        return Err("must be at most 255 bytes");
    }
    if input == "." || input == ".." {
        return Err("must not be a dot segment");
    }
    if input.contains('/') {
        return Err("must be a single path segment");
    }
    if input.chars().any(char::is_control) {
        return Err("must not contain control characters");
    }
    Ok(input.to_owned())
}

string_key!(
    /// The decoded last path segment of a calendar object resource (for example `event-1.ics`).
    ///
    /// A single segment of at most 255 bytes without `/` or control characters; it is not a dot segment.
    /// Percent-encoding happens only in `ResourcePath::format`.
    ObjectUri,
    "object uri",
    parse_object_uri
);

impl ObjectUri {
    /// Derives the conventional `{uid}.ics` resource name for a UID, replacing every character outside
    /// `A-Za-z0-9._@:~+=-` with an underscore and shortening the stem so the result fits the segment limit.
    ///
    /// Different UIDs can map to the same name; callers handle the resulting unique violation.
    pub fn for_uid(uid: &Uid) -> Self {
        const SUFFIX: &str = ".ics";
        let stem: String = uid
            .as_str()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || "._@:~+=-".contains(c) {
                    c
                } else {
                    '_'
                }
            })
            .take(255 - SUFFIX.len())
            .collect();
        // Sanitized ASCII text plus a suffix is always a valid segment (never empty, no dot segment).
        Self(format!("{stem}{SUFFIX}"))
    }
}

fn parse_external_key(input: &str) -> Validated {
    if input.is_empty() {
        return Err("must not be empty");
    }
    if input.len() > 200 {
        return Err("must be at most 200 characters");
    }
    if !input
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'~' | b'-'))
    {
        return Err("may only contain letters, digits and . _ : ~ -");
    }
    Ok(input.to_owned())
}

string_key!(
    /// The caller-chosen stable key of an object, used by the management API (`[A-Za-z0-9._:~-]{1,200}`).
    ExternalKey,
    "external key",
    parse_external_key
);

fn parse_uid(input: &str) -> Validated {
    if input.is_empty() {
        return Err("must not be empty");
    }
    if input.len() > 255 {
        return Err("must be at most 255 bytes");
    }
    if input.chars().any(char::is_control) {
        return Err("must not contain control characters");
    }
    Ok(input.to_owned())
}

string_key!(
    /// An iCalendar `UID`: one to 255 bytes without control characters. Unique per calendar.
    Uid,
    "uid",
    parse_uid
);

impl Uid {
    /// The deterministic UID of an object created through the API: the hyphenated `UUIDv5` of the external key in
    /// the namespace of the calendar id (`UUIDv5(calendar_id, external_key)`).
    pub fn deterministic(calendar: CalendarId, key: &ExternalKey) -> Self {
        let uuid = Uuid::new_v5(&calendar.as_uuid(), key.as_str().as_bytes());
        Self(uuid.hyphenated().to_string())
    }

    /// Wraps a freshly generated UUID (from the `IdGenerator` port) as a UID.
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid.hyphenated().to_string())
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Domain names and e-mail addresses
// ---------------------------------------------------------------------------------------------------------------

fn parse_domain_name(input: &str) -> Validated {
    let lower = input.to_ascii_lowercase();
    if lower.is_empty() {
        return Err("must not be empty");
    }
    if lower.len() > 253 {
        return Err("must be at most 253 characters");
    }
    for label in lower.split('.') {
        if label.is_empty() {
            return Err("must not contain empty labels");
        }
        if label.len() > 63 {
            return Err("labels must be at most 63 characters");
        }
        if !label.bytes().all(|b| is_lower_alnum(b) || b == b'-') {
            return Err("may only contain ASCII letters, digits, hyphens and dots");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("labels must start and end with a letter or digit");
        }
    }
    Ok(lower)
}

string_key!(
    /// A DNS name in lowercase ASCII (internationalized names use their punycode form), for example a tenant's
    /// login or sender domain. No trailing dot.
    DomainName,
    "domain name",
    parse_domain_name
);

fn parse_email(input: &str) -> Validated {
    if input.len() > 254 {
        return Err("must be at most 254 characters");
    }
    let Some((local, domain)) = input.rsplit_once('@') else {
        return Err("must contain exactly one @");
    };
    if local.is_empty() || local.len() > 64 {
        return Err("local part must be 1 to 64 characters");
    }
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return Err("local part must not start or end with a dot or contain two dots");
    }
    let local_ok = local.bytes().all(|b| {
        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-' | b'\'' | b'&' | b'=' | b'~' | b'!')
    });
    if !local_ok {
        return Err("local part contains characters that are not allowed");
    }
    let domain = parse_domain_name(domain).map_err(|_| "domain part is not a valid DNS name")?;
    Ok(format!("{}@{domain}", local.to_ascii_lowercase()))
}

string_key!(
    /// An e-mail address, stored in lowercase (address matching is case-insensitive).
    ///
    /// Accepts a conservative subset of RFC 5322: a local part of letters, digits and `. _ % + - ' & = ~ !` (no
    /// leading, trailing or doubled dots) and an ASCII DNS domain. Nothing that could break out of a header or a
    /// `mailto:` URI is accepted.
    Email,
    "email address",
    parse_email
);

impl Email {
    /// The part before the last `@`.
    pub fn local(&self) -> &str {
        self.0.rsplit_once('@').map_or(self.0.as_str(), |(local, _)| local)
    }

    /// The part after the last `@` (lowercase).
    pub fn domain(&self) -> &str {
        self.0.rsplit_once('@').map_or("", |(_, domain)| domain)
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Calendar user address
// ---------------------------------------------------------------------------------------------------------------

/// The shape of a [`CalendarUserAddress`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressKind {
    /// `mailto:` followed by an e-mail address.
    Mailto,
    /// `urn:uuid:` followed by a principal id.
    UrnUuid,
    /// An absolute `http(s)` URL or a path-absolute URL, typically a principal URL.
    Url,
}

fn strip_prefix_ignore_case<'a>(input: &'a str, prefix: &str) -> Option<&'a str> {
    let head = input.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) {
        input.get(prefix.len()..)
    } else {
        None
    }
}

fn parse_calendar_user_address(input: &str) -> Validated {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("must not be empty");
    }
    if trimmed.len() > CalendarUserAddress::MAX_LEN {
        return Err("must be at most 512 characters");
    }
    if trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("must not contain whitespace or control characters");
    }
    if let Some(rest) = strip_prefix_ignore_case(trimmed, "mailto:") {
        let address = rest.split_once('?').map_or(rest, |(address, _headers)| address);
        let email = parse_email(address).map_err(|_| "mailto address is not a valid e-mail address")?;
        return Ok(format!("mailto:{email}"));
    }
    if let Some(rest) = strip_prefix_ignore_case(trimmed, "urn:uuid:") {
        let uuid = crate::ids::parse_hyphenated(rest).ok_or("urn:uuid must be followed by a hyphenated UUID")?;
        return Ok(format!("urn:uuid:{}", uuid.hyphenated()));
    }
    if trimmed.starts_with('/') && !trimmed.starts_with("//") {
        return Ok(trimmed.to_owned());
    }
    if strip_prefix_ignore_case(trimmed, "http://").is_some() || strip_prefix_ignore_case(trimmed, "https://").is_some()
    {
        let url = url::Url::parse(trimmed).map_err(|_| "is not a valid URL")?;
        if url.host_str().is_none() {
            return Err("URL must have a host");
        }
        // Normalizing can lengthen a URL (a `"` in the fragment becomes `%22`), and what is kept must be accepted again.
        if url.as_str().len() > CalendarUserAddress::MAX_LEN {
            return Err("must be at most 512 characters once normalized (percent-encoded)");
        }
        return Ok(url.to_string());
    }
    Err("must be a mailto:, urn:uuid:, http(s) or path-absolute URI")
}

string_key!(
    /// A normalized calendar user address (`ORGANIZER`, `ATTENDEE`, `calendar-user-address-set`).
    ///
    /// * `mailto:` addresses are lowercased; header fields after `?` are dropped.
    /// * `urn:uuid:` addresses carry a lowercase hyphenated UUID (principal ids).
    /// * `http(s)` URLs and path-absolute URLs (principal URLs) are kept as written, with scheme and host
    ///   normalized for absolute URLs.
    ///
    /// Equality of two normalized addresses is the case-insensitive address match of PLAN 2.6.
    CalendarUserAddress,
    "calendar user address",
    parse_calendar_user_address
);

impl CalendarUserAddress {
    /// The longest calendar user address in bytes. A text of more characters than this is no address and no part of
    /// one, which bounds what a search for addresses looks for.
    pub const MAX_LEN: usize = 512;

    /// The `mailto:` address of an e-mail address.
    pub fn mailto(email: &Email) -> Self {
        Self(format!("mailto:{email}"))
    }

    /// The `urn:uuid:` address of a principal.
    pub fn urn_uuid(principal: crate::ids::PrincipalId) -> Self {
        Self(format!("urn:uuid:{}", principal.as_uuid().hyphenated()))
    }

    /// The shape of this address.
    pub fn kind(&self) -> AddressKind {
        if self.0.starts_with("mailto:") {
            AddressKind::Mailto
        } else if self.0.starts_with("urn:uuid:") {
            AddressKind::UrnUuid
        } else {
            AddressKind::Url
        }
    }

    /// The e-mail address of a `mailto:` address.
    pub fn email(&self) -> Option<Email> {
        self.0.strip_prefix("mailto:").and_then(|rest| Email::parse(rest).ok())
    }

    /// The principal id of a `urn:uuid:` address.
    pub fn principal_id(&self) -> Option<crate::ids::PrincipalId> {
        self.0
            .strip_prefix("urn:uuid:")
            .and_then(|rest| crate::ids::PrincipalId::parse(rest).ok())
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Locale and time zone
// ---------------------------------------------------------------------------------------------------------------

fn parse_locale(input: &str) -> Validated {
    if input.is_empty() {
        return Err("must not be empty");
    }
    if input.len() > 35 {
        return Err("must be at most 35 characters");
    }
    let mut normalized = String::with_capacity(input.len());
    for (index, part) in input.split(['-', '_']).enumerate() {
        if part.is_empty() || part.len() > 8 || !part.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err("must be a BCP 47 language tag such as de or en-GB");
        }
        let alphabetic = part.bytes().all(|b| b.is_ascii_alphabetic());
        if index == 0 {
            if !(2..=3).contains(&part.len()) || !alphabetic {
                return Err("must start with a two or three letter language code");
            }
            normalized.push_str(&part.to_ascii_lowercase());
            continue;
        }
        normalized.push('-');
        if part.len() == 4 && alphabetic {
            // Script subtag: Latn.
            let mut chars = part.chars();
            if let Some(first) = chars.next() {
                normalized.push(first.to_ascii_uppercase());
            }
            normalized.push_str(&chars.as_str().to_ascii_lowercase());
        } else if part.len() == 2 && alphabetic {
            // Region subtag: GB.
            normalized.push_str(&part.to_ascii_uppercase());
        } else {
            normalized.push_str(&part.to_ascii_lowercase());
        }
    }
    Ok(normalized)
}

string_key!(
    /// A BCP 47 language tag such as `de` or `en-GB`, normalized to canonical case (`de-DE`, `zh-Hant-TW`).
    Locale,
    "locale",
    parse_locale
);

impl Locale {
    /// English.
    pub fn en() -> Self {
        Self("en".to_owned())
    }

    /// German.
    pub fn de() -> Self {
        Self("de".to_owned())
    }

    /// The primary language subtag (`de` for `de-DE`).
    pub fn language(&self) -> &str {
        self.0.split('-').next().unwrap_or(&self.0)
    }
}

/// An IANA time zone name (`Europe/Berlin`, `UTC`), validated against the bundled time zone database.
///
/// Names are case-sensitive as in the database. Windows zone names are mapped to IANA names by `davhaven-ical`
/// before they reach this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, JsonSchema)]
#[schemars(with = "String")]
pub struct TimeZoneName(Tz);

impl TimeZoneName {
    /// Looks the name up in the time zone database.
    ///
    /// # Errors
    ///
    /// Returns a [`KeyError`] for names that are not in the database.
    pub fn parse(input: &str) -> Result<Self, KeyError> {
        input
            .parse::<Tz>()
            .map(Self)
            .map_err(|_| KeyError::new("time zone", "is not an IANA time zone name"))
    }

    /// Coordinated Universal Time.
    pub const fn utc() -> Self {
        Self(Tz::UTC)
    }

    /// The canonical name.
    pub fn as_str(&self) -> &'static str {
        self.0.name()
    }

    /// The zone for use with `chrono`.
    pub const fn tz(self) -> Tz {
        self.0
    }
}

impl Default for TimeZoneName {
    fn default() -> Self {
        Self::utc()
    }
}

impl PartialOrd for TimeZoneName {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TimeZoneName {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl fmt::Display for TimeZoneName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TimeZoneName {
    type Err = KeyError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

impl Serialize for TimeZoneName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TimeZoneName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------------------------------------------
// ETag, Schedule-Tag, content hash
// ---------------------------------------------------------------------------------------------------------------

/// Number of base64url characters of the SHA-256 digest kept in an ETag.
const ETAG_CHARS: usize = 22;

fn parse_etag(input: &str) -> Validated {
    let Some(inner) = input.strip_prefix('"').and_then(|rest| rest.strip_suffix('"')) else {
        return Err("must be a quoted strong entity tag");
    };
    if inner.len() != ETAG_CHARS
        || !inner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("must contain exactly 22 base64url characters");
    }
    Ok(input.to_owned())
}

string_key!(
    /// A strong entity tag: `"` + the first 22 characters of base64url(SHA-256(stored bytes)) + `"`.
    ///
    /// Foreign tags (weak tags, other lengths) are rejected; callers treat a tag that fails to parse as a
    /// precondition that cannot match.
    ETag,
    "etag",
    parse_etag
);

impl ETag {
    /// Computes the tag of the exact bytes that are stored (identical in GET, PROPFIND, REPORT and the API).
    pub fn from_bytes(data: &[u8]) -> Self {
        let digest = Sha256::digest(data);
        let encoded = URL_SAFE_NO_PAD.encode(digest.as_slice());
        let short: String = encoded.chars().take(ETAG_CHARS).collect();
        Self(format!("\"{short}\""))
    }

    /// The tag without the surrounding quotes.
    pub fn opaque(&self) -> &str {
        self.0.trim_matches('"')
    }
}

fn parse_schedule_tag(input: &str) -> Validated {
    let Some(inner) = input.strip_prefix('"').and_then(|rest| rest.strip_suffix('"')) else {
        return Err("must be a quoted opaque tag");
    };
    if inner.is_empty() || inner.len() > 64 {
        return Err("must contain 1 to 64 characters");
    }
    if !inner
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("may only contain letters, digits, hyphens and underscores");
    }
    Ok(input.to_owned())
}

string_key!(
    /// The `Schedule-Tag` of a scheduling object resource (RFC 6638): a quoted opaque token that changes on
    /// organizer-initiated changes and on attendee changes to their own copy.
    ScheduleTag,
    "schedule tag",
    parse_schedule_tag
);

impl ScheduleTag {
    /// Builds a fresh tag from a UUID obtained from the `IdGenerator` port.
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(format!("\"{}\"", uuid.simple()))
    }
}

fn parse_content_hash(input: &str) -> Validated {
    if input.len() != 64 || !input.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f')) {
        return Err("must be 64 lowercase hexadecimal digits");
    }
    Ok(input.to_owned())
}

string_key!(
    /// The SHA-256 content hash of an object ignoring volatile properties (DTSTAMP, LAST-MODIFIED, SEQUENCE,
    /// PRODID), as 64 lowercase hexadecimal digits. Equal hashes make an API or sync-engine upsert a no-op.
    ContentHash,
    "content hash",
    parse_content_hash
);

impl ContentHash {
    /// Encodes a 32-byte SHA-256 digest.
    pub fn from_digest(digest: [u8; 32]) -> Self {
        let mut hex = String::with_capacity(64);
        for byte in digest {
            for nibble in [byte >> 4, byte & 0x0f] {
                hex.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
            }
        }
        Self(hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepts<T: FromStr<Err = KeyError> + fmt::Debug>(input: &str) -> T {
        input
            .parse::<T>()
            .unwrap_or_else(|err| panic!("{input:?} should be accepted: {err}"))
    }

    fn rejects<T: FromStr<Err = KeyError> + fmt::Debug>(input: &str) {
        assert!(input.parse::<T>().is_err(), "{input:?} should be rejected");
    }

    #[test]
    fn tenant_slug_rules() {
        for ok in ["a", "acme", "acme-gmbh", "a1", "0", "x-1-y", &"a".repeat(63)] {
            let slug: TenantSlug = accepts(ok);
            assert_eq!(slug.as_str(), ok);
        }
        for bad in ["", "-a", "a-", "Acme", "a_b", "a.b", "a b", "ä", "a/b", &"a".repeat(64)] {
            rejects::<TenantSlug>(bad);
        }
    }

    #[test]
    fn principal_name_rules() {
        for ok in ["anna", "anna.schmidt", "a_b-c", "x1", "0", "a.b.c"] {
            accepts::<PrincipalName>(ok);
        }
        for bad in [
            "",
            ".a",
            "a.",
            "-a",
            "a-",
            "_a",
            "Anna",
            "a@b",
            "a b",
            "a/b",
            "ä",
            &"a".repeat(65),
        ] {
            rejects::<PrincipalName>(bad);
        }
        assert_eq!(
            PrincipalName::from_login("  Anna.Schmidt ").unwrap().as_str(),
            "anna.schmidt"
        );
        assert!(PrincipalName::from_login("anna@acme").is_err());
    }

    #[test]
    fn calendar_slug_rules() {
        for ok in ["personal", "Team_1", "5D8F1C2E-1A2B-4C3D-8E9F-0123456789AB", "a.b", "x"] {
            accepts::<CalendarSlug>(ok);
        }
        for bad in ["", ".hidden", "a b", "a/b", "ä", "a:b", &"a".repeat(101)] {
            rejects::<CalendarSlug>(bad);
        }
        for reserved in [
            "inbox",
            "outbox",
            "notifications",
            "dropbox",
            "Inbox",
            "OUTBOX",
            "NotifICATIONS",
        ] {
            rejects::<CalendarSlug>(reserved);
            assert!(CalendarSlug::is_reserved(reserved));
        }
        assert!(!CalendarSlug::is_reserved("inbox2"));
        accepts::<CalendarSlug>("inbox2");
    }

    #[test]
    fn object_uri_rules() {
        for ok in [
            "event.ics",
            "a@b.ics",
            "mit Leerzeichen.ics",
            "über.ics",
            "100%.ics",
            "x",
            &"a".repeat(255),
        ] {
            accepts::<ObjectUri>(ok);
        }
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            "a\nb",
            "a\0b",
            "a\u{7f}b",
            &"a".repeat(256),
            &"ä".repeat(128),
        ] {
            rejects::<ObjectUri>(bad);
        }
    }

    #[test]
    fn object_uri_for_uid_is_a_valid_sanitized_name() {
        let uid: Uid = accepts("a/b c@example.com");
        let uri = ObjectUri::for_uid(&uid);
        assert_eq!(uri.as_str(), "a_b_c@example.com.ics");
        let long: Uid = accepts(&"u".repeat(255));
        let uri = ObjectUri::for_uid(&long);
        assert_eq!(uri.as_str().len(), 255);
        assert_eq!(
            uri.as_str().rsplit_once('.').map(|(_, extension)| extension),
            Some("ics")
        );
        assert!(ObjectUri::parse(uri.as_str()).is_ok());
        let umlaut: Uid = accepts("äöü");
        assert_eq!(ObjectUri::for_uid(&umlaut).as_str(), "___.ics");
    }

    #[test]
    fn external_key_rules() {
        for ok in ["a", "booking:123", "A.b_c~d-e", &"k".repeat(200)] {
            accepts::<ExternalKey>(ok);
        }
        for bad in ["", "a b", "a/b", "a@b", "ä", &"k".repeat(201)] {
            rejects::<ExternalKey>(bad);
        }
    }

    #[test]
    fn uid_rules_and_deterministic_derivation() {
        accepts::<Uid>("20260101T000000Z-1234@example.com");
        accepts::<Uid>("  has spaces but is accepted verbatim ");
        for bad in ["", "a\r\nb", "a\tb", &"u".repeat(256)] {
            rejects::<Uid>(bad);
        }
        let calendar = CalendarId::parse("018f3c1e-7b2a-7c3d-9e4f-0123456789ab").unwrap();
        let key: ExternalKey = accepts("booking:42");
        let a = Uid::deterministic(calendar, &key);
        let b = Uid::deterministic(calendar, &key);
        assert_eq!(a, b);
        assert_eq!(a.as_str().len(), 36);
        let other: ExternalKey = accepts("booking:43");
        assert_ne!(a, Uid::deterministic(calendar, &other));
        let other_calendar = CalendarId::parse("018f3c1e-7b2a-7c3d-9e4f-0123456789ac").unwrap();
        assert_ne!(a, Uid::deterministic(other_calendar, &key));
        // UUIDv5 is version 5, variant RFC 4122.
        let parsed = Uuid::parse_str(a.as_str()).unwrap();
        assert_eq!(parsed.get_version_num(), 5);
    }

    #[test]
    fn domain_name_rules() {
        assert_eq!(accepts::<DomainName>("Example.ORG").as_str(), "example.org");
        accepts::<DomainName>("localhost");
        accepts::<DomainName>("xn--bcher-kva.example");
        for bad in [
            "",
            ".",
            "a..b",
            "-a.com",
            "a-.com",
            "a_b.com",
            "a b.com",
            "bücher.example",
            "example.org.",
            &format!("{}.com", "a".repeat(64)),
        ] {
            rejects::<DomainName>(bad);
        }
    }

    #[test]
    fn email_rules_and_normalization() {
        let email: Email = accepts("Anna.Schmidt+cal@Example.ORG");
        assert_eq!(email.as_str(), "anna.schmidt+cal@example.org");
        assert_eq!(email.local(), "anna.schmidt+cal");
        assert_eq!(email.domain(), "example.org");
        accepts::<Email>("o'neil@example.org");
        accepts::<Email>("a@localhost");
        for bad in [
            "",
            "plain",
            "@example.org",
            "a@",
            "a@@b.com",
            "a b@example.org",
            "a@exa mple.org",
            ".a@example.org",
            "a.@example.org",
            "a..b@example.org",
            "a\r\nBcc: x@y.z@example.org",
            "a?subject=x@example.org",
            "a,b@example.org",
            "<a@example.org>",
            "ä@example.org",
            "a@bücher.example",
            &format!("{}@example.org", "a".repeat(65)),
        ] {
            rejects::<Email>(bad);
        }
    }

    #[test]
    fn calendar_user_address_normalization() {
        let mailto: CalendarUserAddress = accepts("MAILTO:Anna@Example.ORG");
        assert_eq!(mailto.as_str(), "mailto:anna@example.org");
        assert_eq!(mailto.kind(), AddressKind::Mailto);
        assert_eq!(mailto.email().unwrap().as_str(), "anna@example.org");
        assert_eq!(
            accepts::<CalendarUserAddress>("mailto:anna@example.org?subject=Hi&cc=x@y.z"),
            mailto
        );
        assert_eq!(accepts::<CalendarUserAddress>("  mailto:anna@example.org  "), mailto);

        let principal = crate::ids::PrincipalId::parse("018f3c1e-7b2a-7c3d-9e4f-0123456789ab").unwrap();
        let urn = CalendarUserAddress::urn_uuid(principal);
        assert_eq!(urn.as_str(), "urn:uuid:018f3c1e-7b2a-7c3d-9e4f-0123456789ab");
        assert_eq!(
            accepts::<CalendarUserAddress>("URN:UUID:018F3C1E-7B2A-7C3D-9E4F-0123456789AB"),
            urn
        );
        assert_eq!(urn.kind(), AddressKind::UrnUuid);
        assert_eq!(urn.principal_id(), Some(principal));
        assert_eq!(mailto.principal_id(), None);

        let path: CalendarUserAddress = accepts("/dav/principals/acme/anna/");
        assert_eq!(path.kind(), AddressKind::Url);
        assert_eq!(path.email(), None);
        let url: CalendarUserAddress = accepts("HTTPS://Example.ORG/dav/principals/acme/anna/");
        assert_eq!(url.as_str(), "https://example.org/dav/principals/acme/anna/");

        let built = CalendarUserAddress::mailto(&Email::parse("Bob@Example.org").unwrap());
        assert_eq!(built.as_str(), "mailto:bob@example.org");
    }

    #[test]
    fn a_url_that_normalization_lengthens_past_the_maximum_is_refused() {
        // A fragment of quotes is written as `%22`: 200 characters become 600, and what is kept must parse again (the fuzz
        // target of the share request found a sharee whose address was accepted once and refused the second time).
        let long = format!("https://example.org/x#{}", "\"".repeat(200));
        assert!(long.len() <= CalendarUserAddress::MAX_LEN);
        rejects::<CalendarUserAddress>(&long);
        assert_eq!(
            long.parse::<CalendarUserAddress>().unwrap_err().reason(),
            "must be at most 512 characters once normalized (percent-encoded)",
            "the client sent fewer than 512 characters, and the reason must not say it sent more"
        );
        let fits = format!("https://example.org/x#{}", "\"".repeat(100));
        let address: CalendarUserAddress = accepts(&fits);
        assert!(address.as_str().len() <= CalendarUserAddress::MAX_LEN);
        assert_eq!(accepts::<CalendarUserAddress>(address.as_str()), address);
    }

    #[test]
    fn calendar_user_address_rejections() {
        for bad in [
            "",
            "anna@example.org",
            "mailto:",
            "mailto:not an address",
            "mailto:a@b.c\r\nBcc: x@y.z",
            "urn:uuid:not-a-uuid",
            "ftp://example.org/x",
            "//example.org/x",
            "javascript:alert(1)",
            "https://",
            &format!("mailto:{}@example.org", "a".repeat(600)),
        ] {
            rejects::<CalendarUserAddress>(bad);
        }
    }

    #[test]
    fn locale_normalization() {
        assert_eq!(accepts::<Locale>("DE").as_str(), "de");
        assert_eq!(accepts::<Locale>("de_de").as_str(), "de-DE");
        assert_eq!(accepts::<Locale>("en-gb").as_str(), "en-GB");
        assert_eq!(accepts::<Locale>("zh-hant-tw").as_str(), "zh-Hant-TW");
        assert_eq!(accepts::<Locale>("es-419").as_str(), "es-419");
        assert_eq!(accepts::<Locale>("de-DE").language(), "de");
        assert_eq!(Locale::de().as_str(), "de");
        assert_eq!(Locale::en().as_str(), "en");
        for bad in [
            "",
            "d",
            "deutsch",
            "de-",
            "-de",
            "de--DE",
            "de-D$",
            "1e",
            "de-DEUTSCHLAND",
            &format!("de-{}", "x".repeat(40)),
        ] {
            rejects::<Locale>(bad);
        }
    }

    #[test]
    fn time_zone_names_come_from_the_database() {
        assert_eq!(TimeZoneName::parse("Europe/Berlin").unwrap().as_str(), "Europe/Berlin");
        assert_eq!(TimeZoneName::parse("UTC").unwrap(), TimeZoneName::utc());
        assert_eq!(TimeZoneName::default(), TimeZoneName::utc());
        for bad in [
            "",
            "Europe/Atlantis",
            "europe/berlin",
            "W. Europe Standard Time",
            "CET\n",
        ] {
            rejects::<TimeZoneName>(bad);
        }
        let zone: TimeZoneName = accepts("America/New_York");
        assert_eq!(zone.tz(), Tz::America__New_York);
        assert_eq!(serde_json::to_string(&zone).unwrap(), "\"America/New_York\"");
        assert_eq!(
            serde_json::from_str::<TimeZoneName>("\"America/New_York\"").unwrap(),
            zone
        );
        assert!(serde_json::from_str::<TimeZoneName>("\"Mars/Base\"").is_err());
        assert!(TimeZoneName::parse("Africa/Cairo").unwrap() < TimeZoneName::parse("Europe/Berlin").unwrap());
    }

    #[test]
    fn etag_is_derived_from_the_stored_bytes() {
        let a = ETag::from_bytes(b"BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n");
        let b = ETag::from_bytes(b"BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n");
        let c = ETag::from_bytes(b"BEGIN:VCALENDAR\nEND:VCALENDAR\n");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.as_str().len(), 24);
        assert!(a.as_str().starts_with('"') && a.as_str().ends_with('"'));
        assert_eq!(a.opaque().len(), 22);
        assert_eq!(ETag::parse(a.as_str()).unwrap(), a);
        // SHA-256 of the empty string is e3b0c442 98fc1c14 ... : base64url starts with 47DEQpj8HBSa-_TImW.
        assert_eq!(ETag::from_bytes(b"").as_str(), "\"47DEQpj8HBSa-_TImW-5JC\"");
    }

    #[test]
    fn etag_parse_rejects_foreign_tags() {
        for bad in [
            "",
            "abc",
            "\"abc\"",
            "W/\"47DEQpj8HBSa-_TImW-5JC\"",
            "47DEQpj8HBSa-_TImW-5JC",
            "\"47DEQpj8HBSa-_TImW-5J+\"",
            "\"47DEQpj8HBSa-_TImW-5JCx\"",
        ] {
            rejects::<ETag>(bad);
        }
    }

    #[test]
    fn schedule_tag_rules() {
        let uuid = Uuid::parse_str("018f3c1e-7b2a-7c3d-9e4f-0123456789ab").unwrap();
        let tag = ScheduleTag::from_uuid(uuid);
        assert_eq!(tag.as_str(), "\"018f3c1e7b2a7c3d9e4f0123456789ab\"");
        assert_eq!(ScheduleTag::parse(tag.as_str()).unwrap(), tag);
        for bad in [
            "",
            "abc",
            "\"\"",
            "\"a b\"",
            "W/\"abc\"",
            &format!("\"{}\"", "a".repeat(65)),
        ] {
            rejects::<ScheduleTag>(bad);
        }
    }

    #[test]
    fn content_hash_rules() {
        let hash = ContentHash::from_digest([0xab; 32]);
        assert_eq!(hash.as_str(), "ab".repeat(32));
        assert_eq!(ContentHash::from_digest([0x00; 32]).as_str(), "0".repeat(64));
        assert_eq!(ContentHash::parse(hash.as_str()).unwrap(), hash);
        for bad in [
            "",
            "AB".repeat(32).as_str(),
            "zz".repeat(32).as_str(),
            "ab".repeat(31).as_str(),
        ] {
            rejects::<ContentHash>(bad);
        }
    }

    #[test]
    fn serde_validates_on_deserialize() {
        let slug: TenantSlug = serde_json::from_str("\"acme\"").unwrap();
        assert_eq!(serde_json::to_string(&slug).unwrap(), "\"acme\"");
        let err = serde_json::from_str::<TenantSlug>("\"Not Valid\"").unwrap_err();
        assert!(err.to_string().contains("tenant slug"), "{err}");
        assert!(serde_json::from_str::<Email>("\"nope\"").is_err());
        assert!(serde_json::from_str::<Email>("42").is_err());
    }

    #[test]
    fn key_error_exposes_kind_and_reason() {
        let err = TenantSlug::parse("").unwrap_err();
        assert_eq!(err.kind(), "tenant slug");
        assert_eq!(err.reason(), "must not be empty");
        assert_eq!(err.to_string(), "invalid tenant slug: must not be empty");
    }

    mod props {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #[test]
            fn valid_slugs_round_trip(input in "[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?") {
                let slug = TenantSlug::parse(&input).unwrap();
                prop_assert_eq!(slug.as_str(), input.as_str());
            }

            #[test]
            fn parsing_never_panics(input in ".{0,300}") {
                let _ = TenantSlug::parse(&input);
                let _ = PrincipalName::parse(&input);
                let _ = CalendarSlug::parse(&input);
                let _ = ObjectUri::parse(&input);
                let _ = ExternalKey::parse(&input);
                let _ = Uid::parse(&input);
                let _ = Email::parse(&input);
                let _ = CalendarUserAddress::parse(&input);
                let _ = Locale::parse(&input);
                let _ = TimeZoneName::parse(&input);
                let _ = ETag::parse(&input);
                let _ = ScheduleTag::parse(&input);
                let _ = ContentHash::parse(&input);
                let _ = DomainName::parse(&input);
            }

            #[test]
            fn normalization_is_idempotent(input in "[A-Za-z0-9._%+@-]{1,40}") {
                if let Ok(email) = Email::parse(&input) {
                    prop_assert_eq!(Email::parse(email.as_str()).unwrap(), email);
                }
                if let Ok(locale) = Locale::parse(&input) {
                    prop_assert_eq!(Locale::parse(locale.as_str()).unwrap(), locale);
                }
                if let Ok(address) = CalendarUserAddress::parse(&format!("mailto:{input}")) {
                    prop_assert_eq!(CalendarUserAddress::parse(address.as_str()).unwrap(), address);
                }
            }

            #[test]
            fn urls_are_kept_in_a_form_that_parses_to_itself(
                host in "[A-Za-z0-9]{1,12}(\\.[a-z]{2,6}){0,2}",
                rest in "[!-~]{0,520}",
            ) {
                for scheme in ["http://", "HTTPS://"] {
                    if let Ok(address) = CalendarUserAddress::parse(&format!("{scheme}{host}/{rest}")) {
                        prop_assert!(address.as_str().len() <= CalendarUserAddress::MAX_LEN);
                        prop_assert_eq!(CalendarUserAddress::parse(address.as_str()).unwrap(), address);
                    }
                }
            }
        }
    }
}
