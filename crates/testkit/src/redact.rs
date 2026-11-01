//! Keeping secrets out of what a run reports.
//!
//! A failed case shows the start of the answer the server gave, so that a person sees what went wrong. When the failure is
//! "a refused request was answered with a created credential", that answer holds the credential, in the report of a CI job
//! and (against a deployed instance) as a credential that is still valid. [`secrets`] replaces every secret of a known format
//! in a text before it is stored in a report or an error: the typed tokens of PLAN 2.6 (`dvh_pat_…`, `dvh_feed_…`,
//! `dvh_rsvp_…`), webhook secrets (`whsec_…`), app passwords (seven groups of four characters) and the values of the JSON
//! fields that carry a secret (`password`, `secret`, `feed_url`, `url` of a feed token, `signing_secret`).

use core::fmt::Write as _;

/// What replaces a secret.
const REDACTED: &str = "<redacted>";

/// The prefixes of the typed secrets (PLAN 2.6): the secret runs on up to the first character that cannot be part of one.
const TYPED_PREFIXES: [&str; 4] = ["dvh_pat_", "dvh_feed_", "dvh_rsvp_", "whsec_"];

/// The JSON fields whose value is a secret.
const SECRET_FIELDS: [&str; 5] = ["password", "secret", "feed_url", "signing_secret", "previous_secret"];

/// Whether `character` can be part of the text of a typed secret.
const fn is_secret_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '+' | '/' | '=')
}

/// `text` with every secret of a known format replaced by `<redacted>`.
#[must_use]
pub fn secrets(text: &str) -> String {
    let typed = typed_secrets(text);
    let passwords = app_passwords(&typed);
    json_fields(&passwords)
}

/// The typed secrets: the prefix stays (it says what was there), everything after it goes.
fn typed_secrets(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        let next = TYPED_PREFIXES
            .iter()
            .filter_map(|prefix| rest.find(prefix).map(|at| (at, *prefix)))
            .min_by_key(|(at, _)| *at);
        let Some((at, prefix)) = next else {
            out.push_str(rest);
            break;
        };
        let (before, from) = rest.split_at(at);
        out.push_str(before);
        out.push_str(prefix);
        out.push_str(REDACTED);
        let after = from.get(prefix.len()..).unwrap_or_default();
        let secret_len: usize = after
            .chars()
            .take_while(|character| is_secret_character(*character))
            .map(char::len_utf8)
            .sum();
        rest = after.get(secret_len..).unwrap_or_default();
    }
    out
}

/// App passwords: seven groups of four lowercase base32 characters (`abcd-efgh-…`).
fn app_passwords(text: &str) -> String {
    const GROUPS: usize = 7;
    const GROUP: usize = 4;
    let characters: Vec<char> = text.chars().collect();
    let is_group_character = |character: char| character.is_ascii_lowercase() || ('2'..='7').contains(&character);
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while at < characters.len() {
        let length = GROUPS * GROUP + (GROUPS - 1);
        let candidate = characters.get(at..at + length);
        let bounded_before = at == 0
            || characters
                .get(at - 1)
                .is_none_or(|before| !before.is_ascii_alphanumeric() && *before != '-');
        let bounded_after = characters
            .get(at + length)
            .is_none_or(|after| !after.is_ascii_alphanumeric() && *after != '-');
        let is_password = bounded_before
            && bounded_after
            && candidate.is_some_and(|candidate| {
                candidate.iter().enumerate().all(|(position, character)| {
                    if (position + 1) % (GROUP + 1) == 0 {
                        *character == '-'
                    } else {
                        is_group_character(*character)
                    }
                })
            });
        if is_password {
            out.push_str(REDACTED);
            at += length;
        } else if let Some(character) = characters.get(at) {
            out.push(*character);
            at += 1;
        }
    }
    out
}

/// The values of the JSON fields that carry a secret: `"password": "…"` becomes `"password": "<redacted>"`.
fn json_fields(text: &str) -> String {
    let mut out = text.to_owned();
    for field in SECRET_FIELDS {
        out = redact_field(&out, field);
    }
    out
}

fn redact_field(text: &str, field: &str) -> String {
    let needle = format!("\"{field}\"");
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(&needle) {
        let (before, from) = rest.split_at(at);
        out.push_str(before);
        out.push_str(&needle);
        let after = from.get(needle.len()..).unwrap_or_default();
        let trimmed = after.trim_start();
        let Some(value) = trimmed.strip_prefix(':').map(str::trim_start) else {
            rest = after;
            continue;
        };
        let Some(quoted) = value.strip_prefix('"') else {
            // `null`, a number or an object: nothing to hide in a scalar that is not text.
            let skipped = after.len() - value.len();
            out.push_str(after.get(..skipped).unwrap_or_default());
            rest = value;
            continue;
        };
        let mut end = None;
        let mut escaped = false;
        for (index, character) in quoted.char_indices() {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                end = Some(index);
                break;
            }
        }
        let skipped = after.len() - value.len();
        out.push_str(after.get(..skipped).unwrap_or_default());
        let _ = write!(out, "\"{REDACTED}\"");
        rest = match end {
            Some(index) => quoted.get(index + 1..).unwrap_or_default(),
            None => "",
        };
    }
    out.push_str(rest);
    out
}

/// The start of a text on one line, with secrets removed: whitespace is collapsed and the text is cut at `max` characters.
#[must_use]
pub fn excerpt(text: &str, max: usize) -> String {
    let flat: String = secrets(text).split_whitespace().collect::<Vec<_>>().join(" ");
    let mut shown: String = flat.chars().take(max).collect();
    if flat.chars().count() > max {
        shown.push_str("...");
    }
    shown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_tokens_lose_their_text_and_keep_their_kind() {
        let text =
            "token dvh_pat_abcdefghijkl_0123456789012345678901234567890123456789012 and dvh_feed_x_y, whsec_QUJDREVG=";
        let shown = secrets(text);
        assert_eq!(
            shown,
            "token dvh_pat_<redacted> and dvh_feed_<redacted>, whsec_<redacted>"
        );
    }

    #[test]
    fn app_passwords_are_recognised_by_their_shape_and_other_text_is_left_alone() {
        let password = "abcd-efgh-ijkl-mnop-qrst-uvwx-2345";
        assert_eq!(
            secrets(&format!("the password {password}.")),
            "the password <redacted>."
        );
        // Six groups, an uppercase letter and a longer run are no app passwords.
        assert_eq!(
            secrets("abcd-efgh-ijkl-mnop-qrst-uvwx"),
            "abcd-efgh-ijkl-mnop-qrst-uvwx"
        );
        assert_eq!(
            secrets("abcd-efgh-ijkl-mnop-qrst-uvwx-2345-abcd"),
            "abcd-efgh-ijkl-mnop-qrst-uvwx-2345-abcd"
        );
        assert_eq!(
            secrets("Abcd-efgh-ijkl-mnop-qrst-uvwx-2345"),
            "Abcd-efgh-ijkl-mnop-qrst-uvwx-2345"
        );
    }

    #[test]
    fn the_values_of_secret_fields_are_hidden_whatever_they_look_like() {
        let body = r#"{"id":"1","password":"not in any format","feed_url":"https://x.example/feeds/a.ics","n":1,"secret" : "a\"b","label":"keep"}"#;
        assert_eq!(
            secrets(body),
            r#"{"id":"1","password":"<redacted>","feed_url":"<redacted>","n":1,"secret" : "<redacted>","label":"keep"}"#
        );
        assert_eq!(secrets(r#"{"secret":null}"#), r#"{"secret":null}"#);
    }

    #[test]
    fn an_excerpt_is_flat_short_and_free_of_secrets() {
        let text = "{\"password\":\"x\",\n \"detail\":\"a long story that goes on and on\"}";
        let shown = excerpt(text, 40);
        assert!(shown.starts_with("{\"password\":\"<redacted>\", \"detail\""), "{shown}");
        assert!(shown.ends_with("..."), "{shown}");
        assert!(!shown.contains('\n'));
        assert_eq!(excerpt("short", 40), "short");
    }
}
