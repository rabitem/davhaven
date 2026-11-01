//! What the authenticator makes of a presented credential: classification by the formats of PLAN 2.6.
//!
//! The formats themselves (markers, lengths, the split into prefix and secret, what is hashed, and the generation
//! from random bytes) are defined **once**, in `davhaven_domain::credential_format`, which the application mints
//! credentials with and every authenticator verifies with; this module does not repeat any of it. It only answers
//! the questions of the authentication chain:
//!
//! * is the value one of ours, so that this authenticator decides, or does it carry no marker of ours, so that
//!   another authenticator of the chain may try it ([`TokenShape::Unrecognized`], [`AuthOutcome::NotApplicable`] in the
//!   chain)?
//! * if it carries a marker of ours, is it well formed, and what are its prefix (which finds the row) and its secret
//!   (which is hashed)?
//!
//! The parsers are strict about shape and lenient about nothing but what the domain parser says is lenient: the
//! case of an app password, surrounding whitespace and the hyphens between its groups (people type them). They
//! never panic on any input.
//!
//! [`AuthOutcome::NotApplicable`]: davhaven_ports::AuthOutcome::NotApplicable

use davhaven_domain::{AppPasswordText, CredentialKind, TokenText};
use secrecy::SecretString;

/// The token kinds, in the order they are tried.
const TOKEN_KINDS: [CredentialKind; 3] = [
    CredentialKind::ApiToken,
    CredentialKind::FeedToken,
    CredentialKind::RsvpToken,
];

/// A well-formed app password.
#[derive(Clone)]
pub struct ParsedAppPassword {
    /// The first two groups, which find the row (`abcd-efgh`).
    pub prefix: String,
    /// The whole password in its canonical form (lowercase, single hyphens): the value that is hashed.
    pub secret: SecretString,
}

impl core::fmt::Debug for ParsedAppPassword {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ParsedAppPassword(<redacted>)")
    }
}

/// Parses an app password as a person types it (see the module documentation).
pub fn parse_app_password(text: &str) -> Option<ParsedAppPassword> {
    let password = AppPasswordText::parse(text)?;
    Some(ParsedAppPassword {
        prefix: password.prefix().to_owned(),
        secret: SecretString::from(password.expose()),
    })
}

/// A well-formed token of one of the token kinds.
#[derive(Clone)]
pub struct ParsedToken {
    /// The kind the marker names.
    pub kind: CredentialKind,
    /// The 12 characters after the marker, which find the row.
    pub prefix: String,
    /// The 43 characters after the prefix: the value that is hashed.
    pub secret: SecretString,
}

impl core::fmt::Debug for ParsedToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ParsedToken")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// What a presented token string is.
#[derive(Debug, Clone)]
pub enum TokenShape {
    /// A well-formed token.
    Valid(ParsedToken),
    /// Starts with the marker of a kind but is not well formed (wrong length or characters).
    Malformed(CredentialKind),
    /// Carries no marker of ours: it may belong to another authenticator.
    Unrecognized,
}

/// Whether `text` starts with the marker of `kind` (`dvh_pat_`, `dvh_feed_`, `dvh_rsvp_`).
fn carries_marker(text: &str, kind: CredentialKind) -> bool {
    TokenText::marker(kind).is_some_and(|marker| {
        text.strip_prefix("dvh_")
            .and_then(|rest| rest.strip_prefix(marker))
            .is_some_and(|rest| rest.starts_with('_'))
    })
}

/// Classifies a token string by its marker and checks the shape of the rest.
pub fn parse_token(text: &str) -> TokenShape {
    for kind in TOKEN_KINDS {
        if !carries_marker(text, kind) {
            continue;
        }
        return match TokenText::parse(kind, text) {
            Some(token) => TokenShape::Valid(ParsedToken {
                kind,
                prefix: token.prefix().to_owned(),
                secret: SecretString::from(token.secret()),
            }),
            None => TokenShape::Malformed(kind),
        };
    }
    TokenShape::Unrecognized
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use secrecy::ExposeSecret as _;

    use super::*;

    const PASSWORD: &str = "abcd-efgh-ijkl-mnop-qrst-uvwx-yz23-abcd-efgh";
    const SECRET: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_abcde";
    const TOKEN: &str = "dvh_pat_abcdefghijkl_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_abcde";

    #[test]
    fn app_passwords_have_nine_groups_and_a_two_group_prefix() {
        let parsed = parse_app_password(PASSWORD).unwrap();
        assert_eq!(parsed.prefix, "abcd-efgh");
        assert_eq!(parsed.secret.expose_secret(), PASSWORD);
        assert_eq!(format!("{parsed:?}"), "ParsedAppPassword(<redacted>)");
    }

    #[test]
    fn people_may_type_capitals_spaces_around_and_no_hyphens() {
        for typed in [
            "  ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-ABCD-EFGH\n",
            "abcdefghijklmnopqrstuvwxyz23abcdefgh",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ23ABCDEFGH",
        ] {
            let parsed = parse_app_password(typed).unwrap();
            assert_eq!(
                parsed.secret.expose_secret(),
                PASSWORD,
                "{typed:?}: the canonical form is hashed"
            );
            assert_eq!(parsed.prefix, "abcd-efgh");
        }
    }

    #[test]
    fn malformed_app_passwords_are_not_passwords() {
        for bad in [
            "",
            "abcd",
            "abcd-efgh-ijkl-mnop-qrst-uvwx",
            // The seven groups of the format before 1.0 carry too few secret bits and are no longer accepted.
            "abcd-efgh-ijkl-mnop-qrst-uvwx-yz23",
            "abcd-efgh-ijkl-mnop-qrst-uvwx-yz23-abcd-efgh-ijkl",
            "abcd-efgh-ijkl-mnop-qrst-uvwx-yz23-abcd-efg",
            "abcd-efgh-ijkl-mnop-qrst-uvwx-yz23-abcd-efghi",
            "abcd-efgh-ijkl-mnop-qrst-uvwx-yz23-abcd-efg1",
            "abcd-efgh-ijkl-mnop-qrst-uvwx-yz23-abcd-efg!",
            "abcd efgh ijkl mnop qrst uvwx yz23 abcd efgh",
            "abcd--efgh-ijkl-mnop-qrst-uvwx-yz23-abcd-efgh",
            "abcde-fgh-ijkl-mnop-qrst-uvwx-yz23-abcd-efgh",
            "ünïc-ödéé-ijkl-mnop-qrst-uvwx-yz23-abcd-efgh",
            TOKEN,
        ] {
            assert!(parse_app_password(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn tokens_split_into_marker_prefix_and_secret() {
        let TokenShape::Valid(token) = parse_token(TOKEN) else {
            panic!("a valid token");
        };
        assert_eq!(token.kind, CredentialKind::ApiToken);
        assert_eq!(token.prefix, "abcdefghijkl");
        assert_eq!(token.secret.expose_secret(), SECRET);
        assert!(!format!("{token:?}").contains("0123456789"));
        for (marker, kind) in [
            ("dvh_feed_", CredentialKind::FeedToken),
            ("dvh_rsvp_", CredentialKind::RsvpToken),
        ] {
            let text = TOKEN.replace("dvh_pat_", marker);
            let TokenShape::Valid(token) = parse_token(&text) else {
                panic!("a valid {marker} token");
            };
            assert_eq!(token.kind, kind);
        }
    }

    #[test]
    fn the_secret_may_contain_the_separator_character() {
        // `_` is in the base64url alphabet; the prefix has a fixed length, so the split is not ambiguous.
        let token = format!("dvh_feed_abcdefghijkl_{}", "_".repeat(43));
        assert_eq!(token.len(), "dvh_feed_".len() + 12 + 1 + 43);
        let TokenShape::Valid(parsed) = parse_token(&token) else {
            panic!("valid");
        };
        assert_eq!(parsed.secret.expose_secret().len(), 43);
        assert_eq!(parsed.prefix, "abcdefghijkl");
    }

    #[test]
    fn a_marker_with_a_bad_body_is_malformed_and_a_foreign_value_is_unrecognized() {
        let bad_tokens = [
            "dvh_pat_".to_owned(),
            "dvh_pat_abcdefghijkl".to_owned(),
            "dvh_pat_abcdefghijkl_".to_owned(),
            "dvh_pat_abcdefghijkl_short".to_owned(),
            format!("dvh_pat_ABCDEFGHIJKL_{SECRET}"),
            format!("dvh_pat_abcdefghijk1_{SECRET}"),
            format!("dvh_pat_abcdefghijkl-{SECRET}"),
            format!("dvh_pat_abcdefghijkl_{SECRET}f"),
            format!("dvh_pat_abcdefghijkl_{}", SECRET.replace('e', "+")),
            format!("dvh_pat_abcdefghijkl_{}", SECRET.replace('a', " ")),
            format!("dvh_pat_äbcdefghijk_{SECRET}"),
            format!("dvh_pat_abcdefghijkl_{}ä", SECRET.get(..42).unwrap()),
        ];
        for bad in &bad_tokens {
            assert!(
                matches!(parse_token(bad), TokenShape::Malformed(CredentialKind::ApiToken)),
                "{bad:?}"
            );
        }
        for foreign in [
            "",
            "eyJhbGciOiJIUzI1NiJ9.e30.x",
            "Bearer dvh_pat_x",
            "dvh_other_x",
            "dvh_pat",
            "dvh_patx_abc",
            "DVH_PAT_x",
            PASSWORD,
        ] {
            assert!(matches!(parse_token(foreign), TokenShape::Unrecognized), "{foreign:?}");
        }
    }

    #[test]
    fn what_the_application_mints_parses_the_way_it_was_minted() {
        // The domain module is the one definition: what it builds from random bytes, the authenticator accepts.
        let password =
            AppPasswordText::from_random(&[7; davhaven_domain::credential_format::APP_PASSWORD_RANDOM_BYTES]).unwrap();
        let parsed = parse_app_password(password.expose()).unwrap();
        assert_eq!(parsed.prefix, password.prefix());
        assert_eq!(parsed.secret.expose_secret(), password.expose());
        for kind in TOKEN_KINDS {
            let token = TokenText::from_random(kind, &[3; 8], &[9; 32]).unwrap();
            let TokenShape::Valid(parsed) = parse_token(&token.expose()) else {
                panic!("{kind} parses");
            };
            assert_eq!((parsed.kind, parsed.prefix.as_str()), (kind, token.prefix()));
            assert_eq!(parsed.secret.expose_secret(), token.secret());
        }
    }

    #[test]
    fn fixture_credentials_have_the_documented_formats() {
        use davhaven_fixtures::world::{api_token_secret, app_password_secret, feed_token_secret, rsvp_token_secret};
        assert!(parse_app_password(&app_password_secret("anna")).is_some());
        for (text, kind) in [
            (api_token_secret("admin"), CredentialKind::ApiToken),
            (feed_token_secret("anna"), CredentialKind::FeedToken),
            (rsvp_token_secret("guest"), CredentialKind::RsvpToken),
        ] {
            let TokenShape::Valid(parsed) = parse_token(&text) else {
                panic!("{text} is a valid token");
            };
            assert_eq!(parsed.kind, kind);
        }
    }

    proptest! {
        #[test]
        fn no_input_makes_the_parsers_panic(text in ".{0,120}") {
            let _ = parse_app_password(&text);
            let _ = parse_token(&text);
        }

        #[test]
        fn minted_credentials_always_parse(seed in any::<u8>()) {
            let bytes: Vec<u8> = (0..32_u8).map(|n| seed.wrapping_add(n.wrapping_mul(31))).collect();
            let password = AppPasswordText::from_random(&bytes).unwrap();
            prop_assert!(parse_app_password(password.expose()).is_some());
            for kind in TOKEN_KINDS {
                let token = TokenText::from_random(kind, &bytes, &bytes).unwrap();
                prop_assert!(matches!(parse_token(&token.expose()), TokenShape::Valid(parsed) if parsed.kind == kind));
            }
        }
    }
}
