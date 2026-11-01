//! The MIME structure of iMIP mails (PLAN 2.14, 3.3).
//!
//! Every message is assembled with a fixed date and `Message-ID`, so the bytes are the same on every run and the
//! snapshots (`tests/snapshots`) review the whole message: header order, RFC 2047 encoded words, transfer
//! encodings, the nesting of the parts. Besides the snapshots the tests parse the assembled bytes with a small
//! independent MIME reader and check the structure and the RFC 6047 rules on it.

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "the helpers of an integration test crate are not covered by allow-unwrap-in-tests"
)]

use base64::Engine as _;
use chrono::{DateTime, TimeZone, Utc};
use davhaven_domain::{
    CalendarPart, Email, ExtraHeader, HeaderName, HeaderText, ItipMethod, MailAttachment, Mailbox, MediaType,
    MessageId, OutgoingMail,
};
use davhaven_mime::message::assemble;

fn at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 1, 15, 8, 0, 0).unwrap()
}

fn email(text: &str) -> Email {
    Email::parse(text).unwrap()
}

fn text(value: &str) -> HeaderText {
    HeaderText::parse(value).unwrap()
}

/// A calendar object as the iTIP builder produces it: `CRLF` line ends, folded lines, a `VTIMEZONE`.
fn ics(method: &str, summary: &str) -> String {
    [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//Davhaven//Scheduling//EN",
        "CALSCALE:GREGORIAN",
        &format!("METHOD:{method}"),
        "BEGIN:VTIMEZONE",
        "TZID:Europe/Berlin",
        "BEGIN:STANDARD",
        "DTSTART:19701025T030000",
        "RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU",
        "TZOFFSETFROM:+0200",
        "TZOFFSETTO:+0100",
        "END:STANDARD",
        "BEGIN:DAYLIGHT",
        "DTSTART:19700329T020000",
        "RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU",
        "TZOFFSETFROM:+0100",
        "TZOFFSETTO:+0200",
        "END:DAYLIGHT",
        "END:VTIMEZONE",
        "BEGIN:VEVENT",
        "UID:6f1c0c9e-2f1b-4b0e-9a55-0a6c0a5b7a11",
        "DTSTAMP:20270115T080000Z",
        "DTSTART;TZID=Europe/Berlin:20270112T100000",
        "DTEND;TZID=Europe/Berlin:20270112T113000",
        &format!("SUMMARY:{summary}"),
        "SEQUENCE:1",
        "ORGANIZER;CN=Anna Example:mailto:anna@example.org",
        "ATTENDEE;CN=Guest Example;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:",
        " mailto:guest@example.net",
        "END:VEVENT",
        "END:VCALENDAR",
        "",
    ]
    .join("\r\n")
}

fn invitation(n: u32, method: ItipMethod, subject: &str, text_body: &str, html: &str, summary: &str) -> OutgoingMail {
    let ics = ics(method.as_ical(), summary);
    OutgoingMail {
        message_id: MessageId::parse(&format!("<00000000-0000-7000-8000-00000000000{n}@mail.example.org>")).unwrap(),
        from: Mailbox::named(
            text("Anna Example via Example Organisation"),
            email("noreply@mail.example.org"),
        ),
        sender: None,
        reply_to: Some(Mailbox::named(text("Anna Example"), email("anna@example.org"))),
        to: vec![Mailbox::named(text("Guest Example"), email("guest@example.net"))],
        subject: text(subject),
        text: text_body.to_owned(),
        html: Some(html.to_owned()),
        calendar: Some(CalendarPart {
            method,
            ics: ics.clone(),
        }),
        attachments: vec![MailAttachment {
            filename: text("invite.ics"),
            content_type: MediaType::parse("application/ics").unwrap(),
            data: ics.into_bytes(),
        }],
        headers: vec![
            ExtraHeader {
                name: HeaderName::parse("Content-Class").unwrap(),
                value: text("urn:content-classes:calendarmessage"),
            },
            ExtraHeader {
                name: HeaderName::parse("Auto-Submitted").unwrap(),
                value: text("auto-generated"),
            },
        ],
    }
}

// ---------------------------------------------------------------------------------------------------------------
// A small, independent MIME reader
// ---------------------------------------------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Part {
    headers: Vec<(String, String)>,
    /// The decoded body of a leaf part.
    body: Vec<u8>,
    children: Vec<Part>,
}

impl Part {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn media_type(&self) -> String {
        self.header("content-type")
            .unwrap_or("text/plain")
            .split(';')
            .next()
            .unwrap()
            .trim()
            .to_ascii_lowercase()
    }

    /// A parameter of the content type (`boundary`, `method`, `charset`, `name`).
    fn parameter(&self, name: &str) -> Option<String> {
        let value = self.header("content-type")?;
        value.split(';').skip(1).find_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().trim_matches('"').to_owned())
        })
    }

    /// `type(child,child)` for the whole tree.
    fn outline(&self) -> String {
        if self.children.is_empty() {
            self.media_type()
        } else {
            let children: Vec<String> = self.children.iter().map(Part::outline).collect();
            format!("{}({})", self.media_type(), children.join(","))
        }
    }

    fn find(&self, media_type: &str) -> Option<&Part> {
        if self.media_type() == media_type {
            return Some(self);
        }
        self.children.iter().find_map(|child| child.find(media_type))
    }
}

fn decode_quoted_printable(input: &str) -> Vec<u8> {
    let bytes = input.as_bytes();
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'=' {
            if bytes.get(index + 1) == Some(&b'\r') && bytes.get(index + 2) == Some(&b'\n') {
                index += 3;
                continue;
            }
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap();
            out.push(u8::from_str_radix(hex, 16).unwrap());
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    out
}

fn parse(message: &str) -> Part {
    let (head, body) = message.split_once("\r\n\r\n").unwrap();
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in head.split("\r\n") {
        if line.starts_with(' ') || line.starts_with('\t') {
            let last = headers.last_mut().unwrap();
            last.1.push(' ');
            last.1.push_str(line.trim());
        } else {
            let (name, value) = line.split_once(':').unwrap();
            headers.push((name.to_owned(), value.trim().to_owned()));
        }
    }
    let mut part = Part {
        headers,
        ..Part::default()
    };
    if let Some(boundary) = part.parameter("boundary") {
        let delimiter = format!("--{boundary}");
        let closing = format!("--{boundary}--");
        assert!(body.contains(&closing), "the multipart is closed");
        let after_first = body.split_once(&format!("{delimiter}\r\n")).unwrap().1;
        for section in after_first.split(&format!("\r\n{delimiter}")) {
            let section = section.strip_prefix("\r\n").unwrap_or(section);
            if section.starts_with("--") {
                break;
            }
            part.children.push(parse(section));
        }
    } else {
        part.body = match part
            .header("content-transfer-encoding")
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("base64") => base64::engine::general_purpose::STANDARD
                .decode(body.replace("\r\n", ""))
                .unwrap(),
            Some("quoted-printable") => decode_quoted_printable(body),
            _ => body.as_bytes().to_vec(),
        };
    }
    part
}

fn assembled(mail: &OutgoingMail) -> String {
    String::from_utf8(assemble(mail, at()).unwrap().into_bytes()).unwrap()
}

// ---------------------------------------------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn a_german_invitation_is_a_mixed_message_with_alternatives_and_the_invitation_attached() {
    let mail = invitation(
        1,
        ItipMethod::Request,
        "Einladung: Planungsrunde für Größenänderungen",
        "Anna Example lädt Sie zu einem Termin ein.\n\nWann: Dienstag, 12. Januar 2027, 10:00–11:30 Uhr (Europe/Berlin)\n",
        "<p>Anna Example lädt Sie zu einem Termin ein.</p>\n",
        "Planungsrunde für Größenänderungen",
    );
    insta::assert_snapshot!("invitation_de", assembled(&mail));
}

#[test]
fn an_english_cancellation_declares_the_cancel_method() {
    let mail = invitation(
        2,
        ItipMethod::Cancel,
        "Cancelled: Planning session",
        "Anna Example has cancelled this event.\n",
        "<p>Anna Example has cancelled this event.</p>\n",
        "Planning session",
    );
    insta::assert_snapshot!("cancellation_en", assembled(&mail));
}

#[test]
fn a_reply_is_sent_from_the_attendee_to_the_organizer() {
    let mut mail = invitation(
        3,
        ItipMethod::Reply,
        "Accepted: Planning session",
        "Guest Example has accepted your invitation.\n",
        "<p>Guest Example has accepted your invitation.</p>\n",
        "Planning session",
    );
    mail.from = Mailbox::named(
        text("Guest Example via Example Organisation"),
        email("noreply@mail.example.org"),
    );
    mail.reply_to = Some(Mailbox::bare(email("guest@example.net")));
    mail.to = vec![Mailbox::bare(email("anna@example.org"))];
    insta::assert_snapshot!("reply_en", assembled(&mail));
}

#[test]
fn a_mail_in_organizer_mode_names_the_service_as_sender() {
    let mut mail = invitation(
        4,
        ItipMethod::Request,
        "Invitation: Planning session",
        "Plain text.\n",
        "<p>Plain text.</p>\n",
        "Planning session",
    );
    mail.from = Mailbox::named(text("Anna Example"), email("anna@example.org"));
    mail.sender = Some(Mailbox::bare(email("noreply@mail.example.org")));
    insta::assert_snapshot!("organizer_mode_en", assembled(&mail));
}

#[test]
fn a_plain_text_mail_is_a_single_part() {
    let mut mail = invitation(5, ItipMethod::Request, "Hello", "Just text.\n", "", "x");
    mail.html = None;
    mail.calendar = None;
    mail.attachments.clear();
    mail.headers.clear();
    insta::assert_snapshot!("text_only", assembled(&mail));
}

// ---------------------------------------------------------------------------------------------------------------
// Structure and RFC 6047
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn the_structure_is_the_one_of_the_plan() {
    let mail = invitation(
        1,
        ItipMethod::Request,
        "Invitation",
        "Hello\n",
        "<p>Hello</p>\n",
        "Planning",
    );
    let parsed = parse(&assembled(&mail));
    assert_eq!(
        parsed.outline(),
        "multipart/mixed(multipart/alternative(text/plain,text/html,text/calendar),application/ics)"
    );
    assert_eq!(parsed.header("mime-version"), Some("1.0"));
    assert_eq!(
        parsed.header("content-class"),
        Some("urn:content-classes:calendarmessage")
    );
    assert_eq!(
        parsed.header("message-id"),
        Some("<00000000-0000-7000-8000-000000000001@mail.example.org>")
    );
    assert_eq!(parsed.header("date"), Some("Fri, 15 Jan 2027 08:00:00 +0000"));
    let attachment = &parsed.children[1];
    assert_eq!(attachment.parameter("name").as_deref(), Some("invite.ics"));
    assert!(
        attachment
            .header("content-disposition")
            .unwrap()
            .starts_with("attachment;")
    );
}

#[test]
fn the_calendar_part_reparses_with_the_declared_method() {
    for method in [ItipMethod::Request, ItipMethod::Cancel, ItipMethod::Reply] {
        let mail = invitation(1, method, "Subject", "Text\n", "<p>Text</p>\n", "Planning");
        let parsed = parse(&assembled(&mail));
        let calendar = parsed.find("text/calendar").unwrap();
        assert_eq!(calendar.parameter("method").as_deref(), Some(method.as_ical()));
        assert_eq!(calendar.parameter("charset").as_deref(), Some("UTF-8"));
        let body = String::from_utf8(calendar.body.clone()).unwrap();
        assert!(body.contains(&format!("METHOD:{}\r\n", method.as_ical())), "{body}");
        assert!(
            body.starts_with("BEGIN:VCALENDAR\r\n") && body.ends_with("END:VCALENDAR\r\n"),
            "{body}"
        );
        assert!(body.contains("BEGIN:VTIMEZONE"), "a VTIMEZONE for the TZID");
        let attachment = parsed.find("application/ics").unwrap();
        assert_eq!(
            attachment.body, calendar.body,
            "the attachment is the same calendar object"
        );
    }
}

#[test]
fn bodies_survive_the_transfer_encodings_unchanged() {
    let mut mail = invitation(
        1,
        ItipMethod::Request,
        "Größe",
        "Zeile eins\nZeile zwei mit Umlauten: äöüß € 日本語\n.Ein Punkt am Anfang\n",
        "<p>Größe &amp; Maße</p>\n",
        "Größe",
    );
    mail.text.push_str(&"x".repeat(2000));
    mail.text.push('\n');
    let parsed = parse(&assembled(&mail));
    let plain = parsed.find("text/plain").unwrap();
    let expected = mail.text.replace('\n', "\r\n");
    assert_eq!(String::from_utf8(plain.body.clone()).unwrap(), expected);
    let html = parsed.find("text/html").unwrap();
    assert_eq!(
        String::from_utf8(html.body.clone()).unwrap(),
        "<p>Größe &amp; Maße</p>\r\n"
    );
}

#[test]
fn no_line_of_the_message_exceeds_the_limit_and_every_line_ends_with_crlf() {
    let mut mail = invitation(1, ItipMethod::Request, "Long", "short\n", "<p>short</p>\n", "Long");
    mail.text = format!("{}\n", "word ".repeat(1000));
    mail.subject = text(&"Überlanger Betreff ".repeat(30));
    let message = assembled(&mail);
    assert!(message.is_ascii(), "the message needs no 8BITMIME");
    for line in message.split("\r\n") {
        assert!(
            line.len() <= 998,
            "{} bytes: {}",
            line.len(),
            line.chars().take(40).collect::<String>()
        );
    }
    assert!(!message.replace("\r\n", "").contains('\n'), "a bare line feed");
    assert!(!message.replace("\r\n", "").contains('\r'), "a bare carriage return");
    let (head, _) = message.split_once("\r\n\r\n").unwrap();
    for line in head.split("\r\n") {
        assert!(line.len() <= 78, "a header line of {} bytes: {line}", line.len());
    }
}

#[test]
fn display_names_and_subjects_cannot_inject_headers() {
    // The mail model refuses control characters, so the only way to hand a hostile text to the assembler is the
    // permitted tab and printable characters; they must come out encoded or quoted, never as a new header.
    let mut mail = invitation(
        1,
        ItipMethod::Request,
        "Re: \"quoted\" <angle> ; semicolon, comma",
        "Text\n",
        "<p>x</p>\n",
        "x",
    );
    mail.from = Mailbox::named(
        text("Eve \"The, Hacker\" <evil@example.net>"),
        email("noreply@mail.example.org"),
    );
    let message = assembled(&mail);
    let parsed = parse(&message);
    let names: Vec<&str> = parsed.headers.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "Date",
            "From",
            "Reply-To",
            "To",
            "Subject",
            "Message-ID",
            "Content-Class",
            "Auto-Submitted",
            "MIME-Version",
            "Content-Type"
        ]
    );
    assert!(
        parsed.header("from").unwrap().ends_with("<noreply@mail.example.org>"),
        "{}",
        parsed.header("from").unwrap()
    );
}

#[test]
fn boundaries_are_derived_from_the_message_id() {
    let first = assembled(&invitation(1, ItipMethod::Request, "s", "t\n", "<p>t</p>\n", "x"));
    let again = assembled(&invitation(1, ItipMethod::Request, "s", "t\n", "<p>t</p>\n", "x"));
    let other = assembled(&invitation(2, ItipMethod::Request, "s", "t\n", "<p>t</p>\n", "x"));
    assert_eq!(first, again);
    let boundary = |message: &str| parse(message).parameter("boundary").unwrap();
    assert_ne!(boundary(&first), boundary(&other));
}
