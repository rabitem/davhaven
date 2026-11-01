//! Header encoding and validation.
//!
//! The domain types of the mail model (`HeaderText`, `HeaderName`, `Mailbox`, `Email`) already exclude control
//! characters, so a value can never end a header line. This module turns them into the header types of `lettre`,
//! which encode non-ASCII text as RFC 2047 encoded words and fold long lines, and adds the few headers `lettre`
//! has no type for.

use std::error::Error as StdError;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use davhaven_domain::{Email, ExtraHeader, Mailbox};
use lettre::Address;
use lettre::message::Mailbox as LettreMailbox;
use lettre::message::header::{Header, HeaderName, HeaderValue};

use crate::message::MimeError;

/// The `lettre` address of an e-mail address.
///
/// # Errors
///
/// [`MimeError::Address`] when `lettre` does not accept the address (the domain type is stricter than `lettre`, so
/// this does not happen for validated addresses).
pub fn address(email: &Email) -> Result<Address, MimeError> {
    Address::new(email.local(), email.domain()).map_err(|_| MimeError::Address)
}

/// The `lettre` mailbox of a mail model mailbox. An empty or blank display name is left out.
///
/// # Errors
///
/// [`MimeError::Address`] as for [`address`].
pub fn mailbox(mailbox: &Mailbox) -> Result<LettreMailbox, MimeError> {
    let name = mailbox
        .name
        .as_ref()
        .map(|name| name.as_str().trim())
        .filter(|name| !name.is_empty())
        .map(str::to_owned);
    Ok(LettreMailbox::new(name, address(&mailbox.address)?))
}

/// An additional header as a raw header value (encoded and folded by `lettre`).
///
/// # Errors
///
/// [`MimeError::Header`] when `lettre` rejects the header name.
pub fn extra_header(header: &ExtraHeader) -> Result<HeaderValue, MimeError> {
    let name = HeaderName::new_from_ascii(header.name.as_str().to_owned()).map_err(|_| MimeError::Header)?;
    Ok(HeaderValue::new(name, header.value.as_str().to_owned()))
}

/// The instant of a `Date` header.
///
/// # Errors
///
/// [`MimeError::Date`] for instants before 1970.
pub fn system_time(date: DateTime<Utc>) -> Result<SystemTime, MimeError> {
    let seconds = u64::try_from(date.timestamp()).map_err(|_| MimeError::Date)?;
    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(seconds))
}

/// A `Content-Type` header with parameters exactly as written: the `mime` crate that `lettre` parses types with
/// lowercases them, but `method=REQUEST` of a calendar part is conventionally upper case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawContentType(String);

impl RawContentType {
    /// A `Content-Type` of the given text, for example `text/calendar; charset=UTF-8; method=REQUEST`.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

impl Header for RawContentType {
    fn name() -> HeaderName {
        HeaderName::new_from_ascii_str("Content-Type")
    }

    fn parse(s: &str) -> Result<Self, Box<dyn StdError + Send + Sync>> {
        Ok(Self(s.to_owned()))
    }

    fn display(&self) -> HeaderValue {
        HeaderValue::new(Self::name(), self.0.clone())
    }
}

/// Whether `name` is safe to appear unquoted-free inside a `name="..."` parameter: printable ASCII without quotes,
/// backslashes, semicolons or control characters. Anything else is left out of the `Content-Type` and only
/// travels in the `Content-Disposition`, where `lettre` encodes it (RFC 2231).
pub fn is_plain_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b' ' | b'(' | b')'))
}

/// A 64-bit FNV-1a hash. It only makes MIME boundaries deterministic; it protects nothing.
pub fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// Normalizes line endings to bare `LF`; `lettre` converts them to `CRLF` when it encodes the body.
pub fn normalize_newlines(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use davhaven_domain::{HeaderName as DomainHeaderName, HeaderText};

    use super::*;

    fn email(text: &str) -> Email {
        Email::parse(text).unwrap()
    }

    #[test]
    fn mailboxes_keep_their_display_names_unless_blank() {
        let named = Mailbox::named(
            HeaderText::parse("Anna Müller via Acme").unwrap(),
            email("noreply@mail.example.org"),
        );
        let converted = mailbox(&named).unwrap();
        assert_eq!(converted.name.as_deref(), Some("Anna Müller via Acme"));
        assert_eq!(converted.email.to_string(), "noreply@mail.example.org");
        for blank in ["", "   ", "\t"] {
            let blank = Mailbox::named(HeaderText::parse(blank).unwrap(), email("a@example.org"));
            assert_eq!(mailbox(&blank).unwrap().name, None);
        }
        assert_eq!(
            mailbox(&Mailbox::bare(email("A@Example.ORG")))
                .unwrap()
                .email
                .to_string(),
            "a@example.org"
        );
    }

    #[test]
    fn every_valid_address_character_is_accepted_by_lettre() {
        for local in [
            "a", "a.b", "a+tag", "a_b", "a-b", "o'brien", "a&b", "a=b", "a~b", "a!b", "a%b",
        ] {
            assert!(address(&email(&format!("{local}@example.org"))).is_ok(), "{local}");
        }
    }

    #[test]
    fn dates_convert_and_pre_epoch_dates_are_refused() {
        let at = Utc.with_ymd_and_hms(2027, 1, 15, 8, 0, 0).unwrap();
        assert_eq!(
            system_time(at)
                .unwrap()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            1_800_000_000
        );
        let before = Utc.with_ymd_and_hms(1960, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(system_time(before), Err(MimeError::Date));
    }

    #[test]
    fn extra_headers_are_encoded_not_injected() {
        let header = ExtraHeader {
            name: DomainHeaderName::parse("X-Custom").unwrap(),
            value: HeaderText::parse("Größe für Äpfel").unwrap(),
        };
        let value = extra_header(&header).unwrap();
        let mut headers = lettre::message::header::Headers::new();
        headers.insert_raw(value);
        let text = headers.to_string();
        assert!(text.starts_with("X-Custom: "), "{text}");
        assert!(text.contains("=?utf-8?"), "{text}");
        assert_eq!(text.matches("\r\n").count(), 1, "one header line: {text:?}");
    }

    #[test]
    fn raw_content_types_keep_their_case() {
        let header = RawContentType::new("text/calendar; charset=UTF-8; method=REQUEST");
        let mut headers = lettre::message::header::Headers::new();
        headers.set(header.clone());
        assert_eq!(
            headers.to_string(),
            "Content-Type: text/calendar; charset=UTF-8; method=REQUEST\r\n"
        );
        assert_eq!(RawContentType::parse("a/b").unwrap(), RawContentType::new("a/b"));
    }

    #[test]
    fn file_names_in_content_types_are_conservative() {
        for ok in ["invite.ics", "my file (1).ics", "a-b_c.txt"] {
            assert!(is_plain_file_name(ok), "{ok}");
        }
        for bad in ["", "a\"b.ics", "a\\b", "ä.ics", "a;b", "a\tb", &"x".repeat(101)] {
            assert!(!is_plain_file_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn hashes_and_newlines_are_deterministic() {
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_ne!(fnv1a(b"ab"), fnv1a(b"ba"));
        assert_eq!(normalize_newlines("a\r\nb\rc\nd"), "a\nb\nc\nd");
    }
}
