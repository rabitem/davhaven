//! Serialization of components the server changes; client bytes are otherwise stored verbatim.
//!
//! The server re-serializes only objects it modifies itself (JSON event writes, SCHEDULE-STATUS and PARTSTAT
//! merges, iTIP messages). Output uses `CRLF` line endings, folds lines at 75 octets without splitting UTF-8
//! sequences and escapes text values as RFC 5545 requires.

use crate::error::IcalError;
use crate::parse::ParsedCalendar;

/// Serializes a calendar to RFC 5545 text with `CRLF` line endings.
///
/// The output parses back to an equal calendar (`parse(serialize(c)) == c` is a property test of this
/// crate).
///
/// # Errors
///
/// Never fails today; the `Result` keeps the signature stable.
pub fn serialize(calendar: &ParsedCalendar) -> Result<String, IcalError> {
    Ok(calendar.root.to_calendar().to_string())
}

#[cfg(test)]
mod tests {
    use davhaven_domain::IcalLimits;

    use super::*;
    use crate::parse::parse;

    fn parsed(text: &str) -> ParsedCalendar {
        parse(text.as_bytes(), &IcalLimits::default()).unwrap()
    }

    #[test]
    fn output_uses_crlf_and_folds_at_75_octets() {
        let long = "Ä".repeat(100);
        let calendar = parsed(&format!(
            "BEGIN:VCALENDAR\nVERSION:2.0\nBEGIN:VEVENT\nUID:x\nSUMMARY:{long}\nEND:VEVENT\nEND:VCALENDAR\n"
        ));
        let text = serialize(&calendar).unwrap();
        assert!(text.ends_with("END:VCALENDAR\r\n"));
        assert!(!text.replace("\r\n", "").contains('\n'));
        for line in text.split("\r\n") {
            assert!(line.len() <= 75, "{} octets: {line}", line.len());
        }
        assert_eq!(parsed(&text), calendar);
    }

    #[test]
    fn text_is_escaped_and_survives_a_round_trip() {
        let calendar = parsed(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:x\r\nSUMMARY:One\\, two\\; three\\nfour \\\\ five\r\n\
             DESCRIPTION:Line one\\nLine two\r\nCATEGORIES:A,B\\,C\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
        );
        let text = serialize(&calendar).unwrap();
        assert!(
            text.contains("SUMMARY:One\\, two\\; three\\nfour \\\\ five\r\n"),
            "{text}"
        );
        assert_eq!(parsed(&text), calendar);
        assert_eq!(
            serialize(&parsed(&text)).unwrap(),
            text,
            "serialization is a fixed point"
        );
    }

    #[test]
    fn parameters_values_and_times_survive() {
        let calendar = parsed(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:x\r\nDTSTART;TZID=Europe/Berlin:20270301T100000\r\n\
             DTEND;VALUE=DATE:20270302\r\nATTENDEE;CN=\"Doe, Jane\";PARTSTAT=ACCEPTED;RSVP=TRUE:mailto:jane@example.org\r\n\
             RRULE:FREQ=WEEKLY;BYDAY=MO,WE;COUNT=4\r\nEXDATE;TZID=Europe/Berlin:20270308T100000\r\nX-CUSTOM;X-PARAM=1:custom\r\n\
             END:VEVENT\r\nEND:VCALENDAR\r\n",
        );
        let text = serialize(&calendar).unwrap();
        assert_eq!(parsed(&text), calendar);
        assert!(text.contains("CN=\"Doe, Jane\""), "{text}");
        assert!(text.contains("RRULE:FREQ=WEEKLY;COUNT=4;BYDAY=MO,WE"), "{text}");
    }
}
