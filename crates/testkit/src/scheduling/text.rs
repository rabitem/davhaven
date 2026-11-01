//! Reading and writing the iCalendar text, mail bodies and pages that the scheduling matrix looks at.
//!
//! These are small text functions, not parsers: the matrix looks at lines of an organizer's copy (the `PARTSTAT` and
//! `SCHEDULE-STATUS` of one attendee), at the `METHOD` of a message, at the CSRF field of an RSVP page and at the RSVP
//! links of a mail, and it writes what a calendar client or a mail client would send (an attendee that answers, a
//! `REPLY` as a mail client formats it).

use std::fmt::Write as _;

use davhaven_domain::PartStat;

fn unfolded(text: &str) -> String {
    text.replace("\r\n ", "").replace("\r\n\t", "")
}

fn attendee_line<'a>(text: &'a str, attendee: &str) -> Option<&'a str> {
    let wanted = attendee.to_ascii_lowercase();
    text.lines()
        .find(|line| line.starts_with("ATTENDEE") && line.trim_end().to_ascii_lowercase().ends_with(&wanted))
}

/// The `PARTSTAT` of `attendee` (a `mailto:` address or other calendar user address) in iCalendar text, if the text
/// lists them; a missing parameter is `NEEDS-ACTION`.
pub fn partstat_in(text: &str, attendee: &str) -> Option<PartStat> {
    let text = unfolded(text);
    attendee_line(&text, attendee).map(|line| {
        line.split(':')
            .next()
            .unwrap_or_default()
            .split(';')
            .find_map(|param| param.strip_prefix("PARTSTAT="))
            .and_then(PartStat::from_ical)
            .unwrap_or_default()
    })
}

/// The `SCHEDULE-STATUS` of `attendee` in iCalendar text.
pub fn status_in(text: &str, attendee: &str) -> Option<String> {
    let text = unfolded(text);
    attendee_line(&text, attendee).and_then(|line| {
        line.split(':')
            .next()
            .unwrap_or_default()
            .split(';')
            .find_map(|param| param.strip_prefix("SCHEDULE-STATUS="))
            .map(|value| value.trim_matches('"').to_owned())
    })
}

/// The first value of the property `name` of the text (`SEQUENCE`, `METHOD`, `STATUS`), parameters ignored.
pub fn property_in(text: &str, name: &str) -> Option<String> {
    unfolded(text).lines().find_map(|line| {
        let (head, value) = line.split_once(':')?;
        (head.split(';').next()? == name).then(|| value.to_owned())
    })
}

/// The text with `attendee` answering `partstat`: what a calendar client writes when its user presses a button.
pub fn answered(text: &str, attendee: &str, partstat: PartStat) -> String {
    let text = unfolded(text);
    let wanted = attendee.to_ascii_lowercase();
    let mut out = String::new();
    for line in text.split_inclusive("\r\n") {
        let is_attendee = line.starts_with("ATTENDEE") && line.trim_end().to_ascii_lowercase().ends_with(&wanted);
        match line.split_once(':').filter(|_| is_attendee) {
            Some((params, value)) => {
                let mut kept: Vec<String> = params
                    .split(';')
                    .filter(|param| !param.starts_with("PARTSTAT="))
                    .map(str::to_owned)
                    .collect();
                kept.push(format!("PARTSTAT={}", partstat.as_ical()));
                let _ = write!(out, "{}:{value}", kept.join(";"));
            }
            None => out.push_str(line),
        }
    }
    out
}

/// A `REPLY` as a mail client sends it: `attendee` answers the event `uid` of `organizer`.
pub fn reply_ical(uid: &str, organizer: &str, attendee: &str, partstat: PartStat, sequence: u32) -> String {
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Mail Client//EN\r\nMETHOD:REPLY\r\nBEGIN:VEVENT\r\nUID:{uid}\r\n\
         DTSTAMP:20270301T090000Z\r\nSEQUENCE:{sequence}\r\nORGANIZER:{organizer}\r\n\
         ATTENDEE;PARTSTAT={}:{attendee}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
        partstat.as_ical()
    )
}

/// The CSRF token of a rendered RSVP page, if the page has the form.
pub fn csrf_of(html: &str) -> Option<String> {
    let (_, rest) = html.split_once("name=\"csrf\" value=\"")?;
    Some(rest.split_once('"')?.0.to_owned())
}

/// The RSVP tokens that the links in `text` (the body of a mail) contain, in the order they appear.
pub fn rsvp_tokens_in(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut rest = text;
    while let Some((_, after)) = rest.split_once("/rsvp/dvh_rsvp_") {
        let end = after
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
            .unwrap_or(after.len());
        let (tail, remainder) = after.split_at(end);
        let token = format!("dvh_rsvp_{tail}");
        if !tokens.contains(&token) {
            tokens.push(token);
        }
        rest = remainder;
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    const COPY: &str = "BEGIN:VEVENT\r\nUID:m-1\r\nSEQUENCE:2\r\nATTENDEE;PARTSTAT=NEEDS-ACTION;SCHEDULE-STATUS=1.2:mailto:otto@acme.example\r\n\
        ATTENDEE;CN=\"Guest\":mailto:guest@example.net\r\nEND:VEVENT\r\n";

    #[test]
    fn lines_of_an_attendee_are_read() {
        assert_eq!(
            partstat_in(COPY, "mailto:otto@acme.example"),
            Some(PartStat::NeedsAction)
        );
        assert_eq!(
            partstat_in(COPY, "mailto:OTTO@acme.example"),
            Some(PartStat::NeedsAction),
            "case-insensitive"
        );
        assert_eq!(
            partstat_in(COPY, "mailto:guest@example.net"),
            Some(PartStat::NeedsAction),
            "a missing parameter"
        );
        assert_eq!(partstat_in(COPY, "mailto:nobody@example.net"), None);
        assert_eq!(status_in(COPY, "mailto:otto@acme.example").as_deref(), Some("1.2"));
        assert_eq!(status_in(COPY, "mailto:guest@example.net"), None);
        assert_eq!(property_in(COPY, "SEQUENCE").as_deref(), Some("2"));
    }

    #[test]
    fn an_answer_replaces_the_partstat_of_one_attendee_only() {
        let text = answered(COPY, "mailto:otto@acme.example", PartStat::Declined);
        assert_eq!(partstat_in(&text, "mailto:otto@acme.example"), Some(PartStat::Declined));
        assert_eq!(
            partstat_in(&text, "mailto:guest@example.net"),
            Some(PartStat::NeedsAction)
        );
        assert!(text.contains("SCHEDULE-STATUS=1.2"), "other parameters stay");
        let folded = "ATTENDEE;PARTSTAT=NEEDS-ACTION;CN=A very long name that goes\r\n  on:mailto:a@x.example\r\n";
        assert!(answered(folded, "mailto:a@x.example", PartStat::Accepted).contains("PARTSTAT=ACCEPTED"));
    }

    #[test]
    fn replies_pages_and_mails_are_read() {
        let reply = reply_ical(
            "m-1",
            "mailto:o@x.example",
            "mailto:a@x.example",
            PartStat::Tentative,
            3,
        );
        assert_eq!(property_in(&reply, "METHOD").as_deref(), Some("REPLY"));
        assert_eq!(property_in(&reply, "SEQUENCE").as_deref(), Some("3"));
        assert!(reply.contains("PARTSTAT=TENTATIVE"));
        assert_eq!(
            csrf_of("<input type=\"hidden\" name=\"csrf\" value=\"abc\">").as_deref(),
            Some("abc")
        );
        assert_eq!(csrf_of("<p>no form</p>"), None);
        let mail = "Click https://cal.example.org/rsvp/dvh_rsvp_abc_DEF-1 or <a href=\"https://cal.example.org/rsvp/dvh_rsvp_abc_DEF-1\">here</a> and /rsvp/dvh_rsvp_zzz_Q";
        assert_eq!(rsvp_tokens_in(mail), vec!["dvh_rsvp_abc_DEF-1", "dvh_rsvp_zzz_Q"]);
        assert_eq!(rsvp_tokens_in("nothing"), Vec::<String>::new());
    }
}
