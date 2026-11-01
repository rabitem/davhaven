//! The text formats of server-generated credentials (PLAN 2.6).
//!
//! The application layer mints credentials and the authenticators verify them, so both need one definition of what
//! a credential looks like and of the part that is hashed. This module is that definition; it is pure: the random
//! bytes come from the caller (`IdGenerator::random_bytes`).
//!
//! | Kind | Text | Prefix (finds the row) | Hashed secret |
//! | --- | --- | --- | --- |
//! | App password | nine groups of four lowercase base32 characters, `abcd-efgh-ijkl-mnop-qrst-uvwx-yz23-abcd-efgh` (180 bits) | the first two groups, `abcd-efgh` (40 bits, stored and listed in clear) | the whole text in canonical form (140 secret bits) |
//! | API token | `dvh_pat_{prefix12}_{secret43}` | the 12 characters `prefix12` | `secret43` |
//! | Feed token | `dvh_feed_{prefix12}_{secret43}` | the 12 characters `prefix12` | `secret43` |
//! | RSVP token | `dvh_rsvp_{prefix12}_{secret43}` | the 12 characters `prefix12` | `secret43` |
//!
//! `prefix12` is twelve lowercase base32 characters (60 bits), `secret43` is the unpadded base64url form of 32 random
//! bytes (256 bits). The prefix of an app password is stored and listed in clear, so it does not count toward the 128
//! secret bits that `ENGINEERING_RULES` R6 asks of every server-generated secret: the seven groups after it do
//! ([`APP_PASSWORD_SECRET_BITS`], 140). The secret of a token may contain `_`, so a token is split by position, never
//! by searching for separators. The canonical form of an app password is lowercase with hyphens;
//! [`AppPasswordText::parse`] accepts input a person typed (upper case, without hyphens, surrounding spaces) and
//! returns the canonical text, so every caller hashes the same bytes.
//!
//! Secrets never appear in `Debug` output, are wiped from memory when they are dropped (`zeroize`) and are compared
//! in constant time (`ENGINEERING_RULES` R6).

use core::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::context::CredentialKind;

/// The alphabet of base32 text: RFC 4648 without padding, in lowercase.
const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Groups of an app password.
const GROUPS: usize = 9;

/// The leading groups of an app password that make its prefix: they find the stored row and are shown in clear.
const PREFIX_GROUPS: usize = 2;

/// Characters per group of an app password.
const GROUP_LEN: usize = 4;

/// Bits of randomness in one character of the base32 alphabet.
const BITS_PER_CHAR: usize = 5;

/// The bits of an app password that are secret: everything after the prefix (140).
///
/// `ENGINEERING_RULES` R6 asks for at least 128 secret bits in every server-generated secret. The prefix is stored
/// and listed in clear, so it does not count.
pub const APP_PASSWORD_SECRET_BITS: usize = (GROUPS - PREFIX_GROUPS) * GROUP_LEN * BITS_PER_CHAR;

/// Characters of a token prefix.
pub const TOKEN_PREFIX_LEN: usize = 12;

/// Characters of the secret of a token (32 bytes in unpadded base64url).
pub const TOKEN_SECRET_LEN: usize = 43;

/// Random bytes an app password consumes (184 bits, of which the 180 of its nine groups are used).
pub const APP_PASSWORD_RANDOM_BYTES: usize = 23;

/// Random bytes the prefix of a token consumes.
pub const TOKEN_PREFIX_RANDOM_BYTES: usize = 8;

/// Random bytes the secret of a token consumes.
pub const TOKEN_SECRET_RANDOM_BYTES: usize = 32;

/// Encodes bytes as lowercase base32 without padding.
fn base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let mut buffer: u32 = 0;
    let mut bits = 0_u32;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = usize::try_from((buffer >> bits) & 31).unwrap_or(0);
            out.push(BASE32.get(index).map_or('a', |letter| char::from(*letter)));
        }
        // Only the bits that are not yet written matter; keeping the rest would grow the buffer without bound.
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        let index = usize::try_from((buffer << (5 - bits)) & 31).unwrap_or(0);
        out.push(BASE32.get(index).map_or('a', |letter| char::from(*letter)));
    }
    out
}

fn is_base32(byte: u8) -> bool {
    byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte)
}

/// An app password in its canonical text: nine hyphen-separated groups of four lowercase base32 characters.
#[derive(Clone)]
pub struct AppPasswordText(Zeroizing<String>);

impl PartialEq for AppPasswordText {
    /// Compares in constant time: the text is a secret.
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl Eq for AppPasswordText {}

impl AppPasswordText {
    /// Builds a password from random bytes. Returns `None` when fewer than [`APP_PASSWORD_RANDOM_BYTES`] bytes are
    /// given.
    pub fn from_random(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < APP_PASSWORD_RANDOM_BYTES {
            return None;
        }
        let characters = Zeroizing::new(base32(bytes));
        let mut groups: Vec<&str> = Vec::with_capacity(GROUPS);
        for index in 0..GROUPS {
            let start = index * GROUP_LEN;
            groups.push(characters.get(start..start + GROUP_LEN)?);
        }
        Some(Self(Zeroizing::new(groups.join("-"))))
    }

    /// Reads a password a person typed or a client sent: surrounding whitespace is removed, letters are lowercased
    /// and the hyphens are optional, but where they are present they must separate the nine groups. Returns `None`
    /// unless exactly 36 base32 characters remain.
    pub fn parse(input: &str) -> Option<Self> {
        let text = Zeroizing::new(input.trim().to_ascii_lowercase());
        let characters: Zeroizing<String> =
            Zeroizing::new(text.chars().filter(|character| *character != '-').collect());
        if characters.len() != GROUPS * GROUP_LEN || !characters.bytes().all(is_base32) {
            return None;
        }
        if text.contains('-') {
            let written: Vec<&str> = text.split('-').collect();
            if written.len() != GROUPS || written.iter().any(|group| group.len() != GROUP_LEN) {
                return None;
            }
        }
        let groups: Vec<&str> = (0..GROUPS)
            .filter_map(|index| characters.get(index * GROUP_LEN..(index + 1) * GROUP_LEN))
            .collect();
        Some(Self(Zeroizing::new(groups.join("-"))))
    }

    /// The canonical text; this is what is hashed.
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }

    /// The prefix that finds the stored row: the first two groups, for example `abcd-efgh`.
    pub fn prefix(&self) -> &str {
        self.0
            .get(..GROUP_LEN * PREFIX_GROUPS + (PREFIX_GROUPS - 1))
            .unwrap_or_default()
    }
}

impl fmt::Debug for AppPasswordText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppPasswordText(<redacted>)")
    }
}

/// A token of one of the three token kinds, split into the prefix that finds the row and the secret that is hashed.
#[derive(Clone)]
pub struct TokenText {
    kind: CredentialKind,
    prefix: String,
    secret: Zeroizing<String>,
}

impl PartialEq for TokenText {
    /// Compares in constant time: the secret part is a secret.
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.prefix == other.prefix
            && bool::from(self.secret.as_bytes().ct_eq(other.secret.as_bytes()))
    }
}

impl Eq for TokenText {}

impl TokenText {
    /// The marker after `dvh_` for a token kind; `None` for app passwords, which are not tokens.
    pub const fn marker(kind: CredentialKind) -> Option<&'static str> {
        match kind {
            CredentialKind::ApiToken => Some("pat"),
            CredentialKind::FeedToken => Some("feed"),
            CredentialKind::RsvpToken => Some("rsvp"),
            CredentialKind::AppPassword => None,
        }
    }

    /// Builds a token from random bytes: [`TOKEN_PREFIX_RANDOM_BYTES`] for the prefix and
    /// [`TOKEN_SECRET_RANDOM_BYTES`] for the secret. Returns `None` for app passwords and when a slice is too short.
    pub fn from_random(kind: CredentialKind, prefix_bytes: &[u8], secret_bytes: &[u8]) -> Option<Self> {
        Self::marker(kind)?;
        if prefix_bytes.len() < TOKEN_PREFIX_RANDOM_BYTES || secret_bytes.len() < TOKEN_SECRET_RANDOM_BYTES {
            return None;
        }
        let prefix: String = base32(prefix_bytes).chars().take(TOKEN_PREFIX_LEN).collect();
        let secret = Zeroizing::new(URL_SAFE_NO_PAD.encode(secret_bytes.get(..TOKEN_SECRET_RANDOM_BYTES)?));
        Some(Self { kind, prefix, secret })
    }

    /// Wraps a prefix and a secret that were derived elsewhere (derived RSVP tokens). Returns `None` unless both
    /// have the shape of this format.
    pub fn from_parts(kind: CredentialKind, prefix: &str, secret: &str) -> Option<Self> {
        Self::marker(kind)?;
        let prefix_ok = prefix.len() == TOKEN_PREFIX_LEN && prefix.bytes().all(is_base32);
        let secret_ok = secret.len() == TOKEN_SECRET_LEN
            && secret
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
        (prefix_ok && secret_ok).then(|| Self {
            kind,
            prefix: prefix.to_owned(),
            secret: Zeroizing::new(secret.to_owned()),
        })
    }

    /// Splits token text by position. Returns `None` unless the text has exactly the shape of `kind`.
    pub fn parse(kind: CredentialKind, text: &str) -> Option<Self> {
        let marker = Self::marker(kind)?;
        let rest = text.strip_prefix("dvh_")?.strip_prefix(marker)?.strip_prefix('_')?;
        let prefix = rest.get(..TOKEN_PREFIX_LEN)?;
        let secret = rest.get(TOKEN_PREFIX_LEN..)?.strip_prefix('_')?;
        Self::from_parts(kind, prefix, secret)
    }

    /// The kind of credential the token is.
    pub const fn kind(&self) -> CredentialKind {
        self.kind
    }

    /// The prefix that finds the stored row.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// The secret that is hashed.
    pub fn secret(&self) -> &str {
        self.secret.as_str()
    }

    /// The whole token as it is shown once and presented later. The copy is a plain `String`; a caller that keeps it
    /// for longer than a response wraps it in `Zeroizing`.
    pub fn expose(&self) -> String {
        let marker = Self::marker(self.kind).unwrap_or("pat");
        format!("dvh_{marker}_{}_{}", self.prefix, self.secret.as_str())
    }
}

impl fmt::Debug for TokenText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenText")
            .field("kind", &self.kind)
            .field("prefix", &self.prefix)
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| seed.wrapping_add(u8::try_from(index).unwrap_or(0).wrapping_mul(7)))
            .collect()
    }

    #[test]
    fn app_passwords_have_nine_groups_of_four() {
        let password = AppPasswordText::from_random(&bytes(3, APP_PASSWORD_RANDOM_BYTES)).unwrap();
        let groups: Vec<&str> = password.expose().split('-').collect();
        assert_eq!(groups.len(), 9);
        assert!(groups.iter().all(|group| group.len() == 4));
        assert!(password.expose().bytes().all(|b| b == b'-' || is_base32(b)));
        assert_eq!(password.prefix(), format!("{}-{}", groups[0], groups[1]));
        assert_eq!(password.prefix().len(), 9);
        assert!(AppPasswordText::from_random(&[1; 5]).is_none());
        assert!(AppPasswordText::from_random(&bytes(3, APP_PASSWORD_RANDOM_BYTES - 1)).is_none());
    }

    #[test]
    fn app_passwords_keep_at_least_128_bits_secret_beyond_their_prefix() {
        // R6: the prefix is stored and shown in clear, so it is not part of the secret.
        const { assert!(APP_PASSWORD_SECRET_BITS >= 128) };
        assert_eq!(APP_PASSWORD_SECRET_BITS, 140);
        const {
            assert!(
                APP_PASSWORD_RANDOM_BYTES * 8 >= GROUPS * GROUP_LEN * BITS_PER_CHAR,
                "the random bytes fill every character"
            );
        };
        // The whole password is drawn: a change in the last random bytes that it uses changes the secret part and
        // leaves the prefix alone.
        let a = AppPasswordText::from_random(&bytes(3, APP_PASSWORD_RANDOM_BYTES)).unwrap();
        let mut other = bytes(3, APP_PASSWORD_RANDOM_BYTES);
        other[APP_PASSWORD_RANDOM_BYTES - 2] ^= 0xff;
        let b = AppPasswordText::from_random(&other).unwrap();
        assert_eq!(a.prefix(), b.prefix());
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn typed_passwords_are_normalized_to_the_canonical_form() {
        let password = AppPasswordText::from_random(&bytes(9, APP_PASSWORD_RANDOM_BYTES)).unwrap();
        let canonical = password.expose().to_owned();
        for typed in [
            canonical.clone(),
            canonical.to_ascii_uppercase(),
            format!("  {canonical}\n"),
            canonical.replace('-', ""),
            canonical.replace('-', "").to_ascii_uppercase(),
        ] {
            assert_eq!(AppPasswordText::parse(&typed).unwrap().expose(), canonical, "{typed}");
            assert!(AppPasswordText::parse(&typed).unwrap() == password, "{typed}");
        }
        let other = AppPasswordText::from_random(&bytes(10, APP_PASSWORD_RANDOM_BYTES)).unwrap();
        assert!(other != password, "passwords compare by their text");
        let truncated: String = canonical.chars().take(canonical.len() - 1).collect();
        for bad in [
            String::new(),
            "abcd-efgh".to_owned(),
            truncated,
            format!("{canonical}x"),
            canonical.replacen('-', "--", 1),
            // The seven groups of the format before 1.0 are refused: too short to carry 128 secret bits.
            "abcd-efgh-ijkl-mnop-qrst-uvwx-yz23".to_owned(),
            "abcd-efgh-ijkl-mnop-qrst-uvwx-yz23-abcd-efg".to_owned(),
            "abcd-efgh-ijkl-mnop-qrst-uvwx-yz23-abcd-efg1".to_owned(),
            "abcde-fgh-ijkl-mnop-qrst-uvwx-yz23-abcd-efgh".to_owned(),
        ] {
            assert!(AppPasswordText::parse(&bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn tokens_round_trip_by_position_even_with_underscores_in_the_secret() {
        for kind in [
            CredentialKind::ApiToken,
            CredentialKind::FeedToken,
            CredentialKind::RsvpToken,
        ] {
            let token = TokenText::from_random(kind, &bytes(1, 8), &bytes(0xfb, 32)).unwrap();
            assert_eq!(token.prefix().len(), TOKEN_PREFIX_LEN);
            assert_eq!(token.secret().len(), TOKEN_SECRET_LEN);
            let text = token.expose();
            let text = text.as_str();
            assert!(text.starts_with(&format!("dvh_{}_", TokenText::marker(kind).unwrap())));
            assert_eq!(TokenText::parse(kind, text).unwrap(), token);
            assert_eq!(TokenText::parse(kind, text).unwrap().kind(), kind);
        }
        let with_underscore = TokenText::from_parts(
            CredentialKind::ApiToken,
            "abcdefghijkl",
            &format!("_{}-", "a".repeat(TOKEN_SECRET_LEN - 2)),
        )
        .unwrap();
        let text = with_underscore.expose();
        assert_eq!(
            TokenText::parse(CredentialKind::ApiToken, &text).unwrap(),
            with_underscore
        );
    }

    #[test]
    fn malformed_tokens_are_refused() {
        let token = TokenText::from_random(CredentialKind::ApiToken, &bytes(1, 8), &bytes(2, 32)).unwrap();
        let text = token.expose();
        let text = text.as_str();
        assert!(
            TokenText::parse(CredentialKind::FeedToken, text).is_none(),
            "the kind is part of the format"
        );
        assert!(TokenText::parse(CredentialKind::AppPassword, text).is_none());
        let shortened: String = text.chars().take(text.len() - 1).collect();
        for bad in [
            String::new(),
            "dvh_pat_".to_owned(),
            "dvh_pat_abc_def".to_owned(),
            shortened,
            format!("{text}x"),
            text.replacen("dvh_", "cdx_", 1),
            text.to_ascii_uppercase(),
        ] {
            assert!(TokenText::parse(CredentialKind::ApiToken, &bad).is_none(), "{bad}");
        }
        assert!(TokenText::from_random(CredentialKind::AppPassword, &[0; 8], &[0; 32]).is_none());
        assert!(TokenText::from_random(CredentialKind::ApiToken, &[0; 3], &[0; 32]).is_none());
        assert!(TokenText::from_random(CredentialKind::ApiToken, &[0; 8], &[0; 3]).is_none());
    }

    #[test]
    fn secrets_are_not_debug_printed() {
        let token = TokenText::from_random(CredentialKind::ApiToken, &bytes(1, 8), &bytes(2, 32)).unwrap();
        let shown = format!("{token:?}");
        assert!(!shown.contains(token.secret()), "{shown}");
        assert!(shown.contains(token.prefix()));
        let password = AppPasswordText::from_random(&bytes(4, APP_PASSWORD_RANDOM_BYTES)).unwrap();
        assert!(!format!("{password:?}").contains(password.expose()));
    }

    #[test]
    fn base32_matches_rfc_4648_vectors() {
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "my");
        assert_eq!(base32(b"fo"), "mzxq");
        assert_eq!(base32(b"foo"), "mzxw6");
        assert_eq!(base32(b"foob"), "mzxw6yq");
        assert_eq!(base32(b"fooba"), "mzxw6ytb");
        assert_eq!(base32(b"foobar"), "mzxw6ytboi");
    }
}
