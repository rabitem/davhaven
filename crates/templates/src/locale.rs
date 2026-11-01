//! Locale fallback rules and localized date formatting.
//!
//! A render request names the locale of the recipient or visitor, which may be anything a client sent (`de-AT`,
//! `fr`, `zh-Hant-TW`). The renderer tries, in this order, the locale itself, its language, the configured default
//! locale with its language and finally English, and uses the first one for which the theme has a template
//! ([`fallback_chain`]).
//!
//! Dates and times in mails are formatted by the template function `when(start, end)` and the filters built on
//! the same code ([`format_when`]); German and English are built in, every other language reads like English.
//! The formatting needs no time zone database: the application passes local wall-clock values with the name of
//! their zone, and the zone is printed as it is.

use davhaven_domain::Locale;

/// The locales the formatting functions know: the others read like English.
pub const FORMATTED_LANGUAGES: [&str; 2] = ["de", "en"];

/// The locales to try for a request, most specific first, without duplicates.
///
/// `requested` is tried as it is and by its language (`de-AT`, then `de`); then the configured default locale
/// the same way; English is always the last resort.
pub fn fallback_chain(requested: &Locale, default_locale: &Locale) -> Vec<String> {
    fallback_chain_of(core::slice::from_ref(requested), default_locale)
}

/// The locales to try for a visitor who named several languages, best first: each of them as it is and by its language, in
/// that order, then the configured default locale the same way, and English at the last (see [`fallback_chain`], which is
/// this for one language).
pub fn fallback_chain_of(preferred: &[Locale], default_locale: &Locale) -> Vec<String> {
    let mut chain: Vec<String> = Vec::new();
    for locale in preferred.iter().chain(core::iter::once(default_locale)) {
        for candidate in [locale.as_str(), locale.language()] {
            if !chain.iter().any(|known| known == candidate) {
                chain.push(candidate.to_owned());
            }
        }
    }
    if !chain.iter().any(|known| known == "en") {
        chain.push("en".to_owned());
    }
    chain
}

/// The language a formatting function uses for a resolved locale (`de-AT` formats as `de`, `fr` as `en`).
pub fn formatting_language(locale: &str) -> &'static str {
    let language = locale.split(['-', '_']).next().unwrap_or(locale);
    FORMATTED_LANGUAGES
        .iter()
        .copied()
        .find(|known| known.eq_ignore_ascii_case(language))
        .unwrap_or("en")
}

/// Why a date or time value cannot be formatted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FormatError {
    /// The date is not `YYYY-MM-DD` or does not exist.
    #[error("`{0}` is not a date like 2027-01-12")]
    Date(String),
    /// The time is not `HH:MM`.
    #[error("`{0}` is not a time like 10:00")]
    Time(String),
}

/// A calendar date.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Day {
    year: i32,
    month: u32,
    number: u32,
}

impl Day {
    /// Parses `YYYY-MM-DD`.
    ///
    /// # Errors
    ///
    /// [`FormatError::Date`] for text that is not a date of the proleptic Gregorian calendar.
    pub fn parse(text: &str) -> Result<Self, FormatError> {
        let invalid = || FormatError::Date(text.chars().take(32).collect());
        let mut parts = text.split('-');
        let (Some(year), Some(month), Some(day), None) = (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(invalid());
        };
        // `str::parse` accepts a leading `+`, which is no part of a date.
        if year.len() != 4 || month.len() != 2 || day.len() != 2 || ![year, month, day].iter().all(|part| digits(part))
        {
            return Err(invalid());
        }
        let year: i32 = year.parse().map_err(|_| invalid())?;
        let month: u32 = month.parse().map_err(|_| invalid())?;
        let day: u32 = day.parse().map_err(|_| invalid())?;
        if (1..=12).contains(&month) && day >= 1 && day <= days_in_month(year, month) {
            Ok(Self {
                year,
                month,
                number: day,
            })
        } else {
            Err(invalid())
        }
    }

    /// The weekday, 0 for Monday.
    fn weekday(self) -> usize {
        // Sakamoto's method yields 0 for Sunday.
        const OFFSETS: [i32; 12] = [0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4];
        let year = if self.month < 3 { self.year - 1 } else { self.year };
        let month_index = usize::try_from(self.month.saturating_sub(1)).unwrap_or(0);
        let offset = OFFSETS.get(month_index).copied().unwrap_or(0);
        let day = i32::try_from(self.number).unwrap_or(1);
        let sunday_based = (year + year / 4 - year / 100 + year / 400 + offset + day).rem_euclid(7);
        usize::try_from((sunday_based + 6) % 7).unwrap_or(0)
    }
}

/// Whether `text` is made of ASCII digits only (and is not empty).
fn digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

const fn is_leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

const fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// A time of day.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TimeOfDay {
    hour: u32,
    minute: u32,
}

impl TimeOfDay {
    /// Parses `HH:MM` (seconds are accepted and ignored).
    ///
    /// # Errors
    ///
    /// [`FormatError::Time`] for anything else.
    pub fn parse(text: &str) -> Result<Self, FormatError> {
        let invalid = || FormatError::Time(text.chars().take(32).collect());
        let mut parts = text.split(':');
        let (Some(hour), Some(minute), second, None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
            return Err(invalid());
        };
        if hour.len() != 2
            || minute.len() != 2
            || !digits(hour)
            || !digits(minute)
            || second.is_some_and(|s| s.len() != 2 || !digits(s))
        {
            return Err(invalid());
        }
        let hour: u32 = hour.parse().map_err(|_| invalid())?;
        let minute: u32 = minute.parse().map_err(|_| invalid())?;
        if hour < 24 && minute < 60 {
            Ok(Self { hour, minute })
        } else {
            Err(invalid())
        }
    }
}

/// One end of an event: a date, optionally a time of day and a zone name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Moment {
    /// The day.
    pub day: Day,
    /// The time of day; `None` for all-day values.
    pub time: Option<TimeOfDay>,
    /// The name of the time zone the wall-clock time is in, printed as given.
    pub zone: Option<String>,
}

const WEEKDAYS_DE: [&str; 7] = [
    "Montag",
    "Dienstag",
    "Mittwoch",
    "Donnerstag",
    "Freitag",
    "Samstag",
    "Sonntag",
];
const WEEKDAYS_EN: [&str; 7] = [
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
];
const MONTHS_DE: [&str; 12] = [
    "Januar",
    "Februar",
    "März",
    "April",
    "Mai",
    "Juni",
    "Juli",
    "August",
    "September",
    "Oktober",
    "November",
    "Dezember",
];
const MONTHS_EN: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// A date such as `Tuesday, January 12, 2027` or `Dienstag, 12. Januar 2027`.
pub fn format_date(language: &str, day: Day) -> String {
    let month_index = usize::try_from(day.month.saturating_sub(1)).unwrap_or(0);
    if formatting_language(language) == "de" {
        let weekday = WEEKDAYS_DE.get(day.weekday()).copied().unwrap_or("");
        let month = MONTHS_DE.get(month_index).copied().unwrap_or("");
        format!("{weekday}, {}. {month} {}", day.number, day.year)
    } else {
        let weekday = WEEKDAYS_EN.get(day.weekday()).copied().unwrap_or("");
        let month = MONTHS_EN.get(month_index).copied().unwrap_or("");
        format!("{weekday}, {month} {}, {}", day.number, day.year)
    }
}

/// A time of day such as `10:00 AM` or `10:00 Uhr`.
pub fn format_time(language: &str, clock: TimeOfDay) -> String {
    if formatting_language(language) == "de" {
        format!("{:02}:{:02} Uhr", clock.hour, clock.minute)
    } else {
        let (hour, suffix) = match clock.hour {
            0 => (12, "AM"),
            1..=11 => (clock.hour, "AM"),
            12 => (12, "PM"),
            _ => (clock.hour - 12, "PM"),
        };
        format!("{hour}:{:02} {suffix}", clock.minute)
    }
}

/// The time of day without the unit word, for the first half of a range (`10:00–11:00 Uhr`).
fn bare_time(clock: TimeOfDay) -> String {
    format!("{:02}:{:02}", clock.hour, clock.minute)
}

/// Describes when an event takes place, for a mail or a page.
///
/// * all-day events print the date(s) and `(all day)` / `(ganztägig)`; for several days `end` is the last day
///   (inclusive);
/// * timed events on one day print the date once and the time range;
/// * timed events over several days print both ends in full;
/// * a missing `end` prints the start only;
/// * the zone name, when there is one, follows in parentheses.
pub fn format_when(language: &str, start: &Moment, end: Option<&Moment>) -> String {
    let german = formatting_language(language) == "de";
    let zone = |moment: &Moment| {
        moment
            .zone
            .as_ref()
            .map(|zone| format!(" ({zone})"))
            .unwrap_or_default()
    };
    let Some(start_clock) = start.time else {
        // All-day.
        let label = if german { "ganztägig" } else { "all day" };
        return match end.filter(|end| end.day > start.day) {
            Some(end) => format!(
                "{} – {} ({label})",
                format_date(language, start.day),
                format_date(language, end.day)
            ),
            None => format!("{} ({label})", format_date(language, start.day)),
        };
    };
    let date = format_date(language, start.day);
    let Some(end) = end else {
        return format!("{date}, {}{}", format_time(language, start_clock), zone(start));
    };
    match end.time {
        Some(end_clock) if end.day == start.day => {
            if german {
                format!(
                    "{date}, {}–{}{}",
                    bare_time(start_clock),
                    format_time(language, end_clock),
                    zone(start)
                )
            } else {
                format!(
                    "{date}, {} – {}{}",
                    format_time(language, start_clock),
                    format_time(language, end_clock),
                    zone(start)
                )
            }
        }
        Some(end_clock) => format!(
            "{date}, {} – {}, {}{}",
            format_time(language, start_clock),
            format_date(language, end.day),
            format_time(language, end_clock),
            zone(start)
        ),
        None => format!(
            "{date}, {} – {}{}",
            format_time(language, start_clock),
            format_date(language, end.day),
            zone(start)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locale(text: &str) -> Locale {
        Locale::parse(text).unwrap()
    }

    fn day(text: &str) -> Day {
        Day::parse(text).unwrap()
    }

    #[test]
    fn dates_and_times_are_digits_and_nothing_that_parse_would_still_accept() {
        for bad in [
            "2027-+1-+5",
            "+027-01-12",
            "2027-01-+2",
            "2027- 1-12",
            "2027-0x-12",
            "2027-01-1٣",
        ] {
            assert!(Day::parse(bad).is_err(), "{bad}");
        }
        for bad in ["+9:00", "+9:+0", "09:+0", "09:00:+1", "0x:00", "09:00:"] {
            assert!(TimeOfDay::parse(bad).is_err(), "{bad}");
        }
        assert!(Day::parse("2027-01-12").is_ok());
        assert!(TimeOfDay::parse("09:05:30").is_ok());
    }

    fn moment(date: &str, time: Option<&str>, zone: Option<&str>) -> Moment {
        Moment {
            day: day(date),
            time: time.map(|time| TimeOfDay::parse(time).unwrap()),
            zone: zone.map(str::to_owned),
        }
    }

    #[test]
    fn the_fallback_chain_goes_from_specific_to_english() {
        assert_eq!(
            fallback_chain(&locale("de-AT"), &locale("en")),
            vec!["de-AT", "de", "en"]
        );
        assert_eq!(fallback_chain(&locale("fr"), &locale("de")), vec!["fr", "de", "en"]);
        assert_eq!(
            fallback_chain(&locale("fr-CA"), &locale("de-CH")),
            vec!["fr-CA", "fr", "de-CH", "de", "en"]
        );
        assert_eq!(fallback_chain(&locale("en"), &locale("en")), vec!["en"]);
        assert_eq!(fallback_chain(&locale("de"), &locale("de")), vec!["de", "en"]);
        assert_eq!(
            fallback_chain(&locale("zh-Hant-TW"), &locale("en-GB")),
            vec!["zh-Hant-TW", "zh", "en-GB", "en"]
        );
    }

    #[test]
    fn a_visitor_with_several_languages_gets_the_first_one_that_the_theme_has() {
        assert_eq!(
            fallback_chain_of(&[locale("fr"), locale("de-AT"), locale("en")], &locale("de")),
            vec!["fr", "de-AT", "de", "en"],
            "each language as it is and by its language, in the order the visitor ranked them"
        );
        assert_eq!(
            fallback_chain_of(&[locale("fr")], &locale("de")),
            vec!["fr", "de", "en"]
        );
        assert_eq!(
            fallback_chain_of(&[], &locale("de")),
            vec!["de", "en"],
            "no language named: the deployment's default"
        );
    }

    #[test]
    fn languages_without_formatting_rules_read_like_english() {
        for (locale, language) in [
            ("de", "de"),
            ("de-AT", "de"),
            ("DE", "de"),
            ("en-GB", "en"),
            ("fr", "en"),
            ("", "en"),
        ] {
            assert_eq!(formatting_language(locale), language, "{locale}");
        }
    }

    #[test]
    fn dates_are_validated_and_weekdays_are_right() {
        assert!(Day::parse("2027-01-12").is_ok());
        for bad in [
            "",
            "2027",
            "2027-1-12",
            "2027-13-01",
            "2027-02-29",
            "2027-04-31",
            "2027-01-00",
            "27-01-12",
            "2027/01/12",
            "2027-01-12-01",
            "x027-01-12",
        ] {
            assert!(matches!(Day::parse(bad), Err(FormatError::Date(_))), "{bad}");
        }
        assert!(Day::parse("2028-02-29").is_ok(), "2028 is a leap year");
        assert!(Day::parse("2100-02-29").is_err(), "2100 is not");
        // Known weekdays: 2027-01-12 is a Tuesday, 2024-02-29 a Thursday, 2000-01-01 a Saturday, 1999-12-31 a Friday.
        for (date, weekday) in [
            ("2027-01-12", 1),
            ("2024-02-29", 3),
            ("2000-01-01", 5),
            ("1999-12-31", 4),
            ("2027-03-07", 6),
            ("2027-03-08", 0),
        ] {
            assert_eq!(day(date).weekday(), weekday, "{date}");
        }
    }

    #[test]
    fn times_are_validated() {
        assert!(
            TimeOfDay::parse("00:00").is_ok()
                && TimeOfDay::parse("23:59").is_ok()
                && TimeOfDay::parse("10:00:30").is_ok()
        );
        for bad in [
            "",
            "24:00",
            "10:60",
            "1:00",
            "10",
            "10:0",
            "10:00:3",
            "10:00:00:00",
            "ab:cd",
        ] {
            assert!(matches!(TimeOfDay::parse(bad), Err(FormatError::Time(_))), "{bad}");
        }
    }

    #[test]
    fn dates_and_times_follow_the_conventions_of_the_language() {
        assert_eq!(format_date("en", day("2027-01-12")), "Tuesday, January 12, 2027");
        assert_eq!(format_date("de", day("2027-01-12")), "Dienstag, 12. Januar 2027");
        assert_eq!(format_date("de-AT", day("2027-03-08")), "Montag, 8. März 2027");
        assert_eq!(format_date("fr", day("2027-03-07")), "Sunday, March 7, 2027");
        for (time, english, german) in [
            ("00:05", "12:05 AM", "00:05 Uhr"),
            ("09:30", "9:30 AM", "09:30 Uhr"),
            ("12:00", "12:00 PM", "12:00 Uhr"),
            ("13:45", "1:45 PM", "13:45 Uhr"),
            ("23:59", "11:59 PM", "23:59 Uhr"),
        ] {
            let clock = TimeOfDay::parse(time).unwrap();
            assert_eq!(format_time("en", clock), english);
            assert_eq!(format_time("de", clock), german);
        }
    }

    #[test]
    fn events_read_naturally_in_both_languages() {
        let start = moment("2027-01-12", Some("10:00"), Some("Europe/Berlin"));
        let same_day = moment("2027-01-12", Some("11:30"), Some("Europe/Berlin"));
        let next_day = moment("2027-01-13", Some("09:00"), Some("Europe/Berlin"));
        assert_eq!(
            format_when("en", &start, Some(&same_day)),
            "Tuesday, January 12, 2027, 10:00 AM – 11:30 AM (Europe/Berlin)"
        );
        assert_eq!(
            format_when("de", &start, Some(&same_day)),
            "Dienstag, 12. Januar 2027, 10:00–11:30 Uhr (Europe/Berlin)"
        );
        assert_eq!(
            format_when("en", &start, Some(&next_day)),
            "Tuesday, January 12, 2027, 10:00 AM – Wednesday, January 13, 2027, 9:00 AM (Europe/Berlin)"
        );
        assert_eq!(
            format_when("de", &start, Some(&next_day)),
            "Dienstag, 12. Januar 2027, 10:00 Uhr – Mittwoch, 13. Januar 2027, 09:00 Uhr (Europe/Berlin)"
        );
        assert_eq!(
            format_when("en", &start, None),
            "Tuesday, January 12, 2027, 10:00 AM (Europe/Berlin)"
        );
        let floating = moment("2027-01-12", Some("10:00"), None);
        assert_eq!(
            format_when("de", &floating, None),
            "Dienstag, 12. Januar 2027, 10:00 Uhr"
        );
    }

    #[test]
    fn all_day_events_say_so() {
        let first = moment("2027-01-12", None, None);
        let last = moment("2027-01-14", None, None);
        assert_eq!(format_when("en", &first, None), "Tuesday, January 12, 2027 (all day)");
        assert_eq!(format_when("de", &first, None), "Dienstag, 12. Januar 2027 (ganztägig)");
        assert_eq!(
            format_when("en", &first, Some(&last)),
            "Tuesday, January 12, 2027 – Thursday, January 14, 2027 (all day)"
        );
        assert_eq!(
            format_when("de", &first, Some(&first)),
            "Dienstag, 12. Januar 2027 (ganztägig)",
            "an end on the first day is the same day"
        );
    }
}
