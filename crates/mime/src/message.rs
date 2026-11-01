//! Assembly of the MIME message structure.
//!
//! [`assemble`] turns an [`OutgoingMail`] into the bytes of an RFC 5322 message. The structure is the one of iMIP
//! (PLAN 2.14, RFC 6047):
//!
//! ```text
//! multipart/mixed
//! ├── multipart/alternative
//! │   ├── text/plain; charset=utf-8
//! │   ├── text/html; charset=utf-8                      (when the mail has HTML)
//! │   └── text/calendar; charset=UTF-8; method=REQUEST  (when the mail has a calendar part)
//! └── application/ics; name="invite.ics"                (every attachment)
//! ```
//!
//! Layers that have a single child collapse: a mail without attachments is the `multipart/alternative` alone, and
//! a mail with nothing but text is a single `text/plain` part.
//!
//! Everything that would make the output differ between runs is injected: the `Date` comes from the caller (the
//! transport's clock) and the MIME boundaries are derived from the `Message-ID`, so the same mail assembles to
//! the same bytes.

use chrono::{DateTime, Utc};
use davhaven_domain::{Email, ItipMethod, MailAttachment, MailError, OutgoingMail};
use lettre::Message;
use lettre::message::header::{ContentDisposition, ContentTransferEncoding};
use lettre::message::{Body, MultiPart, SinglePart};

use crate::headers::{
    RawContentType, address, extra_header, fnv1a, is_plain_file_name, mailbox, normalize_newlines, system_time,
};

/// Why a mail cannot be assembled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MimeError {
    /// The mail violates an invariant of the mail model (no recipient, too many recipients, a reserved header).
    #[error("the mail is not valid: {0}")]
    Invalid(#[from] MailError),
    /// An address is not accepted by the encoder.
    #[error("an address cannot be encoded")]
    Address,
    /// A header name is not accepted by the encoder.
    #[error("a header cannot be encoded")]
    Header,
    /// The date is before 1970.
    #[error("the date of the message is out of range")]
    Date,
    /// The calendar part has no `METHOD`, or one that differs from the declared method.
    #[error("the calendar part does not carry the method {expected} (RFC 6047)")]
    MethodMismatch {
        /// The method the mail declares.
        expected: ItipMethod,
    },
    /// The encoder failed to build the message.
    #[error("the message cannot be built")]
    Build,
}

/// A mail as RFC 5322 bytes together with its SMTP envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssembledMail {
    bytes: Vec<u8>,
    envelope_from: Email,
    envelope_to: Vec<Email>,
}

impl AssembledMail {
    /// The message: header, blank line and body, with `CRLF` line endings.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the value and returns the message bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// The SMTP `MAIL FROM`: the `Sender` of the mail when it has one, its `From` otherwise.
    pub const fn envelope_from(&self) -> &Email {
        &self.envelope_from
    }

    /// The SMTP `RCPT TO` addresses: the recipients of the mail, each once.
    pub fn envelope_to(&self) -> &[Email] {
        &self.envelope_to
    }
}

/// Assembles `mail` into an RFC 5322 message dated `date`.
///
/// # Errors
///
/// [`MimeError`]: the mail is invalid, an address or header cannot be encoded, the date is out of range or the
/// calendar part's `METHOD` does not match the declared method.
pub fn assemble(mail: &OutgoingMail, date: DateTime<Utc>) -> Result<AssembledMail, MimeError> {
    mail.validate()?;
    if let Some(calendar) = &mail.calendar {
        check_method(&calendar.ics, calendar.method)?;
    }

    let mut builder = Message::builder().date(system_time(date)?).from(mailbox(&mail.from)?);
    if let Some(sender) = &mail.sender {
        builder = builder.sender(mailbox(sender)?);
    }
    if let Some(reply_to) = &mail.reply_to {
        builder = builder.reply_to(mailbox(reply_to)?);
    }
    for recipient in &mail.to {
        builder = builder.to(mailbox(recipient)?);
    }
    builder = builder
        .subject(mail.subject.as_str().to_owned())
        .message_id(Some(mail.message_id.as_str().to_owned()));
    for header in &mail.headers {
        builder = builder.raw_header(extra_header(header)?);
    }

    let message = match body(mail) {
        Content::Single(part) => builder.singlepart(part),
        Content::Multi(part) => builder.multipart(part),
    }
    .map_err(|_| MimeError::Build)?;

    let envelope_from = mail.sender.as_ref().unwrap_or(&mail.from).address.clone();
    let mut envelope_to: Vec<Email> = Vec::with_capacity(mail.to.len());
    for recipient in mail.recipients() {
        if !envelope_to.contains(recipient) {
            envelope_to.push(recipient.clone());
        }
    }
    // The encoder must accept every envelope address as well.
    for email in std::iter::once(&envelope_from).chain(&envelope_to) {
        address(email)?;
    }
    Ok(AssembledMail {
        bytes: message.formatted(),
        envelope_from,
        envelope_to,
    })
}

/// The body of the message: one part or a multipart.
enum Content {
    Single(SinglePart),
    Multi(MultiPart),
}

fn body(mail: &OutgoingMail) -> Content {
    let text = normalize_newlines(&mail.text);
    let html = mail.html.as_deref().map(normalize_newlines);
    let calendar = mail
        .calendar
        .as_ref()
        .map(|calendar| (calendar.method, normalize_newlines(&calendar.ics)));

    // Every text that ends up in the message unencoded must not contain a boundary.
    let mut avoid: Vec<&[u8]> = vec![text.as_bytes()];
    if let Some(html) = &html {
        avoid.push(html.as_bytes());
    }
    if let Some((_, ics)) = &calendar {
        avoid.push(ics.as_bytes());
    }
    let seed = mail.message_id.as_str();
    let alternative_boundary = pick_boundary(seed, "alt", &avoid);
    let mixed_boundary = pick_boundary(seed, "mixed", &avoid);

    let plain = SinglePart::plain(text);
    let content = if html.is_some() || calendar.is_some() {
        let mut alternative = MultiPart::alternative()
            .boundary(alternative_boundary)
            .singlepart(plain);
        if let Some(html) = html {
            alternative = alternative.singlepart(SinglePart::html(html));
        }
        if let Some((method, ics)) = calendar {
            alternative = alternative.singlepart(calendar_part(method, ics));
        }
        Content::Multi(alternative)
    } else {
        Content::Single(plain)
    };

    if mail.attachments.is_empty() {
        return content;
    }
    let mut mixed = MultiPart::mixed().boundary(mixed_boundary).build();
    mixed = match content {
        Content::Single(part) => mixed.singlepart(part),
        Content::Multi(part) => mixed.multipart(part),
    };
    for attachment in &mail.attachments {
        mixed = mixed.singlepart(attachment_part(attachment));
    }
    Content::Multi(mixed)
}

/// The `text/calendar` alternative of a scheduling mail.
///
/// The text goes out as it is (`7bit`) when it is plain ASCII with short lines, which iCalendar usually is, and as
/// base64 otherwise. Quoted-printable is avoided on purpose: it turns `=` in `RRULE` and `TZID` lines into `=3D`,
/// which some mail gateways and clients that parse the part before decoding it get wrong.
fn calendar_part(method: ItipMethod, ics: String) -> SinglePart {
    let body = Body::new_with_encoding(ics.clone(), ContentTransferEncoding::SevenBit)
        .or_else(|_| Body::new_with_encoding(ics.clone(), ContentTransferEncoding::Base64))
        .unwrap_or_else(|_| Body::new(ics));
    SinglePart::builder()
        .header(RawContentType::new(format!(
            "text/calendar; charset=UTF-8; method={}",
            method.as_ical()
        )))
        .body(body)
}

/// An attachment: base64 for binary content, the best text encoding for text types.
fn attachment_part(attachment: &MailAttachment) -> SinglePart {
    let file_name = attachment.filename.as_str();
    let content_type = if is_plain_file_name(file_name) {
        format!("{}; name=\"{file_name}\"", attachment.content_type)
    } else {
        attachment.content_type.as_str().to_owned()
    };
    let body = Body::new_with_encoding(attachment.data.clone(), ContentTransferEncoding::Base64)
        .unwrap_or_else(|_| Body::new(attachment.data.clone()));
    SinglePart::builder()
        .header(ContentDisposition::attachment(file_name))
        .header(RawContentType::new(content_type))
        .body(body)
}

/// A boundary derived from the message id: stable for a mail, unique per layer, and verified not to occur in the
/// parts that are not transfer-encoded.
fn pick_boundary(seed: &str, layer: &str, avoid: &[&[u8]]) -> String {
    for round in 0_u32..16 {
        let high = fnv1a(format!("{seed}/{layer}/{round}/1").as_bytes());
        let low = fnv1a(format!("{layer}/{round}/{seed}/2").as_bytes());
        let candidate = format!("=_davhaven_{layer}_{high:016x}{low:016x}");
        let needle = candidate.as_bytes();
        let clashes = avoid
            .iter()
            .any(|text| text.windows(needle.len()).any(|window| window == needle));
        if !clashes {
            return candidate;
        }
    }
    // Sixteen clashes with a 128-bit hash cannot happen by accident; the last candidate stays unique per mail.
    format!("=_davhaven_{layer}_{:016x}", fnv1a(seed.as_bytes()))
}

/// Checks that the calendar object carries the method the `Content-Type` declares (RFC 6047 section 2.4).
fn check_method(ics: &str, method: ItipMethod) -> Result<(), MimeError> {
    let declared = declared_method(ics);
    match declared {
        Some(found) if found.eq_ignore_ascii_case(method.as_ical()) => Ok(()),
        _ => Err(MimeError::MethodMismatch { expected: method }),
    }
}

/// The value of the first top-level `METHOD` line of an iCalendar text (continuation lines are ignored).
fn declared_method(ics: &str) -> Option<String> {
    ics.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        let name = name.split(';').next().unwrap_or(name);
        name.eq_ignore_ascii_case("METHOD").then(|| value.trim().to_owned())
    })
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use davhaven_domain::{CalendarPart, ExtraHeader, HeaderName, HeaderText, Mailbox, MediaType, MessageId};

    use super::*;

    fn email(text: &str) -> Email {
        Email::parse(text).unwrap()
    }

    fn at() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2027, 1, 15, 8, 0, 0).unwrap()
    }

    fn mail() -> OutgoingMail {
        OutgoingMail {
            message_id: MessageId::parse("<outbox-1@mail.example.org>").unwrap(),
            from: Mailbox::named(
                HeaderText::parse("Anna via Acme").unwrap(),
                email("noreply@mail.example.org"),
            ),
            sender: None,
            reply_to: Some(Mailbox::bare(email("anna@example.org"))),
            to: vec![Mailbox::bare(email("guest@example.net"))],
            subject: HeaderText::parse("Invitation: Planning").unwrap(),
            text: "Hello\nYou are invited.\n".to_owned(),
            html: None,
            calendar: None,
            attachments: Vec::new(),
            headers: Vec::new(),
        }
    }

    fn ics(method: &str) -> String {
        format!("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:{method}\r\nEND:VCALENDAR\r\n")
    }

    fn text_of(assembled: &AssembledMail) -> String {
        String::from_utf8(assembled.bytes().to_vec()).unwrap()
    }

    #[test]
    fn a_text_mail_is_a_single_part_with_crlf_line_ends() {
        let assembled = assemble(&mail(), at()).unwrap();
        let text = text_of(&assembled);
        assert!(text.starts_with("Date: Fri, 15 Jan 2027 08:00:00 +0000\r\n"), "{text}");
        assert!(text.contains("Message-ID: <outbox-1@mail.example.org>\r\n"));
        assert!(text.contains("MIME-Version: 1.0\r\n"));
        assert!(text.contains("Content-Type: text/plain; charset=utf-8\r\n"));
        assert!(!text.contains("multipart"), "{text}");
        let (header, body) = text.split_once("\r\n\r\n").unwrap();
        assert!(!header.contains("\n\n") && body.ends_with("\r\n"), "{text:?}");
        assert!(
            !text.replace("\r\n", "").contains('\n'),
            "only CRLF line ends: {text:?}"
        );
        assert_eq!(assembled.envelope_from(), &email("noreply@mail.example.org"));
        assert_eq!(assembled.envelope_to(), &[email("guest@example.net")]);
    }

    #[test]
    fn html_and_calendar_alternatives_nest_in_mixed_with_attachments() {
        let mut full = mail();
        full.html = Some("<p>Hello</p>".to_owned());
        full.calendar = Some(CalendarPart {
            method: ItipMethod::Request,
            ics: ics("REQUEST"),
        });
        full.attachments = vec![MailAttachment {
            filename: HeaderText::parse("invite.ics").unwrap(),
            content_type: MediaType::parse("application/ics").unwrap(),
            data: ics("REQUEST").into_bytes(),
        }];
        let text = text_of(&assemble(&full, at()).unwrap());
        let mixed = text.find("multipart/mixed").unwrap();
        let alternative = text.find("multipart/alternative").unwrap();
        let plain = text.find("text/plain").unwrap();
        let html = text.find("text/html").unwrap();
        let calendar = text.find("text/calendar; charset=UTF-8; method=REQUEST").unwrap();
        let attachment = text.find("application/ics; name=\"invite.ics\"").unwrap();
        assert!(
            mixed < alternative && alternative < plain && plain < html && html < calendar && calendar < attachment,
            "{text}"
        );
        assert!(
            text.contains("Content-Disposition: attachment; filename=\"invite.ics\""),
            "{text}"
        );
    }

    #[test]
    fn layers_with_a_single_child_collapse() {
        let mut with_html = mail();
        with_html.html = Some("<p>x</p>".to_owned());
        let text = text_of(&assemble(&with_html, at()).unwrap());
        assert!(
            text.contains("multipart/alternative") && !text.contains("multipart/mixed"),
            "{text}"
        );

        let mut with_attachment = mail();
        with_attachment.attachments = vec![MailAttachment {
            filename: HeaderText::parse("note.txt").unwrap(),
            content_type: MediaType::parse("text/plain").unwrap(),
            data: b"hi".to_vec(),
        }];
        let text = text_of(&assemble(&with_attachment, at()).unwrap());
        assert!(
            text.contains("multipart/mixed") && !text.contains("multipart/alternative"),
            "{text}"
        );
    }

    #[test]
    fn the_same_mail_assembles_to_the_same_bytes() {
        let mut full = mail();
        full.html = Some("<p>x</p>".to_owned());
        full.calendar = Some(CalendarPart {
            method: ItipMethod::Cancel,
            ics: ics("CANCEL"),
        });
        assert_eq!(assemble(&full, at()).unwrap(), assemble(&full, at()).unwrap());
        let mut other = full.clone();
        other.message_id = MessageId::parse("<outbox-2@mail.example.org>").unwrap();
        assert_ne!(
            assemble(&full, at()).unwrap().bytes(),
            assemble(&other, at()).unwrap().bytes()
        );
    }

    #[test]
    fn boundaries_never_occur_in_the_text_they_separate() {
        let seed = "<m@example.org>";
        let first = pick_boundary(seed, "alt", &[]);
        let hostile = format!("line\n--{first}\nmore");
        let second = pick_boundary(seed, "alt", &[hostile.as_bytes()]);
        assert_ne!(first, second);
        assert!(!hostile.contains(&second));
        assert!(first.starts_with("=_davhaven_alt_") && first.len() == "=_davhaven_alt_".len() + 32);
    }

    #[test]
    fn the_calendar_method_must_match_the_declared_method() {
        let mut wrong = mail();
        wrong.calendar = Some(CalendarPart {
            method: ItipMethod::Request,
            ics: ics("CANCEL"),
        });
        assert_eq!(
            assemble(&wrong, at()).unwrap_err(),
            MimeError::MethodMismatch {
                expected: ItipMethod::Request
            }
        );
        let mut missing = mail();
        missing.calendar = Some(CalendarPart {
            method: ItipMethod::Reply,
            ics: "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n".to_owned(),
        });
        assert!(matches!(
            assemble(&missing, at()),
            Err(MimeError::MethodMismatch { .. })
        ));
        let mut lower = mail();
        lower.calendar = Some(CalendarPart {
            method: ItipMethod::Reply,
            ics: "BEGIN:VCALENDAR\r\nmethod:reply\r\nEND:VCALENDAR\r\n".to_owned(),
        });
        assert!(
            assemble(&lower, at()).is_ok(),
            "the property name and value are case-insensitive"
        );
        assert_eq!(
            declared_method("BEGIN:VCALENDAR\r\nMETHOD;X-A=b:PUBLISH\r\n"),
            Some("PUBLISH".to_owned())
        );
        assert_eq!(
            declared_method("BEGIN:VCALENDAR\r\nX-METHOD:A\r\n NOMETHOD:B\r\n"),
            None
        );
    }

    #[test]
    fn invalid_mails_are_refused_before_anything_is_built() {
        let mut none = mail();
        none.to.clear();
        assert_eq!(
            assemble(&none, at()).unwrap_err(),
            MimeError::Invalid(MailError::NoRecipient)
        );
        let mut reserved = mail();
        reserved.headers.push(ExtraHeader {
            name: HeaderName::parse("Subject").unwrap(),
            value: HeaderText::parse("x").unwrap(),
        });
        assert!(matches!(
            assemble(&reserved, at()),
            Err(MimeError::Invalid(MailError::ReservedHeader(_)))
        ));
        let before = Utc.with_ymd_and_hms(1960, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(assemble(&mail(), before).unwrap_err(), MimeError::Date);
    }

    #[test]
    fn the_envelope_uses_the_sender_and_lists_every_recipient_once() {
        let mut service = mail();
        service.sender = Some(Mailbox::bare(email("bounces@mail.example.org")));
        service.to = vec![
            Mailbox::bare(email("a@example.net")),
            Mailbox::bare(email("b@example.net")),
            Mailbox::bare(email("A@example.net")),
        ];
        let assembled = assemble(&service, at()).unwrap();
        assert_eq!(assembled.envelope_from(), &email("bounces@mail.example.org"));
        assert_eq!(
            assembled.envelope_to(),
            &[email("a@example.net"), email("b@example.net")]
        );
        let text = text_of(&assembled);
        assert!(text.contains("Sender: bounces@mail.example.org\r\n"), "{text}");
        assert_eq!(assembled.clone().into_bytes(), assembled.bytes());
    }

    #[test]
    fn non_ascii_text_is_encoded_and_headers_cannot_be_injected() {
        let mut german = mail();
        german.subject = HeaderText::parse("Einladung: Größenänderung").unwrap();
        german.text = "Grüße aus Köln\n".to_owned();
        let text = text_of(&assemble(&german, at()).unwrap());
        let (header, body) = text.split_once("\r\n\r\n").unwrap();
        assert!(header.contains("Subject: Einladung: =?utf-8?"), "{header}");
        assert!(header.is_ascii(), "{header}");
        assert!(
            body.contains("Content-Transfer-Encoding") || text.contains("Content-Transfer-Encoding"),
            "{text}"
        );
        assert!(text.is_ascii(), "the message needs no 8BITMIME: {text}");
        // A subject that tried to inject a header is not constructible at all.
        assert!(HeaderText::parse("x\r\nBcc: evil@example.net").is_err());
    }

    #[test]
    fn attachments_with_unusual_names_keep_a_clean_content_type() {
        let mut odd = mail();
        odd.attachments = vec![MailAttachment {
            filename: HeaderText::parse("Einladung \"Q1\"; äöü.ics").unwrap(),
            content_type: MediaType::parse("application/ics").unwrap(),
            data: b"BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n".to_vec(),
        }];
        let text = text_of(&assemble(&odd, at()).unwrap());
        assert!(text.contains("Content-Type: application/ics\r\n"), "{text}");
        assert!(text.contains("Content-Disposition: attachment;"), "{text}");
        assert!(text.contains("Content-Transfer-Encoding: base64"), "{text}");
        assert!(text.is_ascii(), "{text}");
    }
}
