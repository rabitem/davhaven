//! The few texts the application writes into data on its own, in one place.
//!
//! Almost everything a person reads comes from the template catalog (`TemplateRenderer`, per locale and theme;
//! mails, pages and the busy summary of feeds). What remains here are defaults for data that is created without a
//! person naming it: the name of the personal calendar of a new user, the text of an alarm an event does not
//! describe, and the fallback of the busy summary when the renderer cannot answer. They are defaults, not
//! configuration: a deployment renames a personal calendar through the management API after the fact, a theme
//! replaces the busy summary through its `feed_busy` template.

use davhaven_domain::Locale;

/// The slug of the personal calendar of a user.
pub(crate) const PERSONAL_CALENDAR_SLUG: &str = "personal";

/// The text of an alarm that has none and whose event has no title either.
pub(crate) const DEFAULT_ALARM_TEXT: &str = "Reminder";

/// Whether the language of `locale` is German.
fn german(locale: &Locale) -> bool {
    locale.language().eq_ignore_ascii_case("de")
}

/// The display name of the personal calendar of a new user.
pub(crate) fn personal_calendar_name(locale: &Locale) -> &'static str {
    if german(locale) { "Persönlich" } else { "Personal" }
}

/// The summary of a busy block when the template renderer has no `feed_busy` template to ask.
pub(crate) fn busy_summary(locale: &Locale) -> &'static str {
    if german(locale) { "Beschäftigt" } else { "Busy" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn german_and_every_other_language_have_their_defaults() {
        assert_eq!(personal_calendar_name(&Locale::de()), "Persönlich");
        assert_eq!(personal_calendar_name(&Locale::en()), "Personal");
        assert_eq!(busy_summary(&Locale::de()), "Beschäftigt");
        assert_eq!(busy_summary(&Locale::en()), "Busy");
    }
}
