//! Validation of the text fields of management requests.

use crate::error::{AppError, AppResult, SafeMessage};

/// An invalid request with a client-safe message and no field.
pub(crate) const fn invalid(text: &'static str) -> AppError {
    AppError::invalid(SafeMessage::from_static(text))
}

/// An invalid request that names the field (`pointer`) and the rule (`code`) that was violated.
pub(crate) fn field_error(pointer: &'static str, code: &'static str, text: &'static str) -> AppError {
    invalid(text).with_field_error(pointer, code, SafeMessage::from_static(text))
}

/// A required, single-line name: trimmed, not empty, at most `max` characters, without control characters.
///
/// # Errors
///
/// `Invalid` naming the field.
pub(crate) fn clean_name(pointer: &'static str, value: &str, max: usize) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(field_error(pointer, "empty", "A value is required."));
    }
    if value.chars().count() > max {
        return Err(field_error(pointer, "too-long", "The value is too long."));
    }
    if value.chars().any(char::is_control) {
        return Err(field_error(
            pointer,
            "control-characters",
            "The value must not contain control characters.",
        ));
    }
    Ok(value.to_owned())
}

/// An optional free text that may span lines: blank text is no text, control characters other than line breaks and
/// tabs are refused and the length is limited.
///
/// # Errors
///
/// `Invalid` naming the field.
pub(crate) fn clean_optional_text(pointer: &'static str, value: Option<&str>, max: usize) -> AppResult<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.trim().is_empty() {
        return Ok(None);
    }
    if value.chars().count() > max {
        return Err(field_error(pointer, "too-long", "The value is too long."));
    }
    if value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(field_error(
            pointer,
            "control-characters",
            "The value must not contain control characters.",
        ));
    }
    Ok(Some(value.to_owned()))
}

/// Normalizes a color: `#RRGGBB` or `#RRGGBBAA`, hexadecimal digits in upper case.
///
/// # Errors
///
/// `Invalid` naming the field for any other form.
pub(crate) fn check_color(pointer: &'static str, value: Option<&str>) -> AppResult<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let digits = value.strip_prefix('#').unwrap_or_default();
    if !matches!(digits.len(), 6 | 8) || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(field_error(
            pointer,
            "invalid-color",
            "A color is #RRGGBB or #RRGGBBAA.",
        ));
    }
    Ok(Some(format!("#{}", digits.to_ascii_uppercase())))
}

#[cfg(test)]
mod tests {
    use davhaven_domain::ErrorKind;

    use super::*;

    #[test]
    fn names_are_trimmed_and_checked() {
        assert_eq!(clean_name("/n", "  Work  ", 10).unwrap(), "Work");
        for bad in ["", "   ", "a\u{7}b", "abcdefghijk"] {
            let error = clean_name("/n", bad, 10).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Invalid, "{bad:?}");
            assert_eq!(error.field_errors().first().map(|field| field.pointer), Some("/n"));
        }
    }

    #[test]
    fn free_text_keeps_its_lines_and_drops_blank_values() {
        assert_eq!(clean_optional_text("/d", None, 5).unwrap(), None);
        assert_eq!(clean_optional_text("/d", Some("  \n "), 5).unwrap(), None);
        assert_eq!(
            clean_optional_text("/d", Some("a\nb"), 5).unwrap().as_deref(),
            Some("a\nb")
        );
        assert!(clean_optional_text("/d", Some("abcdef"), 5).is_err());
        assert!(clean_optional_text("/d", Some("a\u{0}"), 5).is_err());
    }

    #[test]
    fn colors_are_normalized_to_upper_case() {
        assert_eq!(check_color("/c", Some("#ff2968")).unwrap().as_deref(), Some("#FF2968"));
        assert_eq!(
            check_color("/c", Some("#FF296880")).unwrap().as_deref(),
            Some("#FF296880")
        );
        assert_eq!(check_color("/c", None).unwrap(), None);
        for bad in ["red", "#12345", "#12345g", "FF2968", "#FF29680", ""] {
            assert!(check_color("/c", Some(bad)).is_err(), "{bad}");
        }
    }
}
