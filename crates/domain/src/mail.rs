//! The outgoing mail model (`OutgoingMail`, mailboxes, header-safe text).
//!
//! `OutgoingMail` is the structured message the iMIP composer hands to a `MailTransport`; the `mime` crate turns
//! it into RFC 5322 bytes. The header newtypes make header injection unrepresentable: they reject CR, LF and
//! every other control character, so a value can never end a header line or start a new header.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::OutboxId;
use crate::keys::{DomainName, Email};
use crate::vocab::ItipMethod;

fn parse_header_text(input: &str) -> Result<String, &'static str> {
    if input.len() > 998 {
        return Err("must be at most 998 bytes");
    }
    if input.chars().any(|c| c.is_control() && c != '\t') {
        return Err("must not contain control characters such as CR or LF");
    }
    Ok(input.to_owned())
}

string_key!(
    /// Text for a header value or a display name: at most 998 bytes, free of CR, LF, NUL and every other control
    /// character (tabs are allowed). Non-ASCII text is fine; the MIME layer encodes it (RFC 2047).
    HeaderText,
    "header text",
    parse_header_text
);

fn parse_header_name(input: &str) -> Result<String, &'static str> {
    if input.is_empty() || input.len() > 64 {
        return Err("must be 1 to 64 characters");
    }
    if !input.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err("may only contain letters, digits and hyphens");
    }
    if input.starts_with('-') || input.ends_with('-') {
        return Err("must start and end with a letter or digit");
    }
    Ok(input.to_owned())
}

string_key!(
    /// The name of an additional mail header: letters, digits and hyphens, for example `X-Mailer`.
    HeaderName,
    "header name",
    parse_header_name
);

fn parse_message_id(input: &str) -> Result<String, &'static str> {
    let Some(inner) = input.strip_prefix('<').and_then(|rest| rest.strip_suffix('>')) else {
        return Err("must be enclosed in angle brackets");
    };
    let Some((left, right)) = inner.split_once('@') else {
        return Err("must have the form <left@right>");
    };
    let left_ok = !left.is_empty()
        && left.len() <= 200
        && left
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+' | b'=' | b'~'));
    if !left_ok {
        return Err("the part before @ may only contain letters, digits and . _ - + = ~");
    }
    let right = DomainName::parse(right).map_err(|_| "the part after @ must be a domain name")?;
    Ok(format!("<{left}@{right}>"))
}

string_key!(
    /// A `Message-ID` header value: `<left@domain>` with a conservative character set.
    MessageId,
    "message id",
    parse_message_id
);

impl MessageId {
    /// The Message-ID of an outbox message: `<{outbox_id}@{sender_domain}>`. Deterministic, so a retried send
    /// carries the same id.
    pub fn for_outbox(outbox: OutboxId, sender_domain: &DomainName) -> Self {
        Self(format!("<{outbox}@{sender_domain}>"))
    }
}

fn parse_media_type(input: &str) -> Result<String, &'static str> {
    let lower = input.to_ascii_lowercase();
    let Some((main, sub)) = lower.split_once('/') else {
        return Err("must have the form type/subtype");
    };
    let token_ok = |part: &str| {
        !part.is_empty()
            && part.len() <= 64
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-' | b'_'))
    };
    if token_ok(main) && token_ok(sub) {
        Ok(lower)
    } else {
        Err("contains characters that are not allowed")
    }
}

string_key!(
    /// A media type without parameters in lowercase, for example `application/ics`.
    MediaType,
    "media type",
    parse_media_type
);

/// An address with an optional display name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Mailbox {
    /// The display name, if any.
    pub name: Option<HeaderText>,
    /// The e-mail address.
    pub address: Email,
}

impl Mailbox {
    /// A mailbox without a display name.
    pub const fn bare(address: Email) -> Self {
        Self { name: None, address }
    }

    /// A mailbox with a display name.
    pub const fn named(name: HeaderText, address: Email) -> Self {
        Self {
            name: Some(name),
            address,
        }
    }
}

/// The calendar alternative of a scheduling mail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CalendarPart {
    /// The iTIP method; written to the `method` parameter of `text/calendar` and to the `METHOD` property.
    pub method: ItipMethod,
    /// The iCalendar text of the message.
    pub ics: String,
}

/// A file attached to a mail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MailAttachment {
    /// The file name.
    pub filename: HeaderText,
    /// The media type.
    pub content_type: MediaType,
    /// The content.
    pub data: Vec<u8>,
}

/// An additional header of a mail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExtraHeader {
    /// The header name.
    pub name: HeaderName,
    /// The header value.
    pub value: HeaderText,
}

/// Why a mail cannot be sent as composed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MailError {
    /// No recipient.
    #[error("the mail has no recipient")]
    NoRecipient,
    /// More recipients than a transport accepts in one message.
    #[error("the mail has too many recipients")]
    TooManyRecipients,
    /// An additional header would override a header the composer owns.
    #[error("header `{0}` is set by the composer and cannot be added")]
    ReservedHeader(String),
}

/// The most recipients one message may have (iMIP sends one message per external attendee).
pub const MAX_RECIPIENTS: usize = 100;

/// Headers the composer and transport own; additional headers may not use these names.
const RESERVED_HEADERS: [&str; 12] = [
    "from",
    "sender",
    "reply-to",
    "to",
    "cc",
    "bcc",
    "subject",
    "message-id",
    "date",
    "mime-version",
    "content-type",
    "content-transfer-encoding",
];

/// A structured outgoing mail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OutgoingMail {
    /// The `Message-ID`; derived from the outbox id so retries are idempotent for receivers.
    pub message_id: MessageId,
    /// The `From` mailbox.
    pub from: Mailbox,
    /// The `Sender` mailbox, when it differs from `From`.
    pub sender: Option<Mailbox>,
    /// The `Reply-To` mailbox.
    pub reply_to: Option<Mailbox>,
    /// The recipients (`To`).
    pub to: Vec<Mailbox>,
    /// The subject.
    pub subject: HeaderText,
    /// The plain-text alternative.
    pub text: String,
    /// The HTML alternative.
    pub html: Option<String>,
    /// The calendar alternative of scheduling mails.
    pub calendar: Option<CalendarPart>,
    /// Attachments (the `invite.ics` copy of the iTIP part, for example).
    pub attachments: Vec<MailAttachment>,
    /// Additional headers such as `Content-Class` or `X-Auto-Response-Suppress`.
    pub headers: Vec<ExtraHeader>,
}

impl OutgoingMail {
    /// Checks the invariants a transport relies on: at least one and at most [`MAX_RECIPIENTS`] recipients, and
    /// no additional header that collides with one the composer owns.
    ///
    /// # Errors
    ///
    /// Returns the first violated invariant as a [`MailError`].
    pub fn validate(&self) -> Result<(), MailError> {
        if self.to.is_empty() {
            return Err(MailError::NoRecipient);
        }
        if self.to.len() > MAX_RECIPIENTS {
            return Err(MailError::TooManyRecipients);
        }
        for header in &self.headers {
            let name = header.name.as_str();
            if RESERVED_HEADERS
                .iter()
                .any(|reserved| reserved.eq_ignore_ascii_case(name))
            {
                return Err(MailError::ReservedHeader(name.to_owned()));
            }
        }
        Ok(())
    }

    /// The e-mail addresses of all recipients.
    pub fn recipients(&self) -> impl Iterator<Item = &Email> {
        self.to.iter().map(|mailbox| &mailbox.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn email(text: &str) -> Email {
        Email::parse(text).unwrap()
    }

    fn mail() -> OutgoingMail {
        OutgoingMail {
            message_id: MessageId::parse("<abc@mail.example.org>").unwrap(),
            from: Mailbox::named(
                HeaderText::parse("Anna via Acme").unwrap(),
                email("noreply@mail.example.org"),
            ),
            sender: None,
            reply_to: Some(Mailbox::bare(email("anna@example.org"))),
            to: vec![Mailbox::bare(email("guest@example.net"))],
            subject: HeaderText::parse("Einladung: Teamtreffen").unwrap(),
            text: "Hallo".to_owned(),
            html: None,
            calendar: Some(CalendarPart {
                method: ItipMethod::Request,
                ics: "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n".to_owned(),
            }),
            attachments: Vec::new(),
            headers: vec![ExtraHeader {
                name: HeaderName::parse("Content-Class").unwrap(),
                value: HeaderText::parse("urn:content-classes:calendarmessage").unwrap(),
            }],
        }
    }

    #[test]
    fn header_text_rejects_anything_that_could_inject_headers() {
        for bad in [
            "a\r\nBcc: x@y.z",
            "a\nb",
            "a\rb",
            "a\0b",
            "a\u{85}b",
            "a\u{7f}b",
            &"x".repeat(999),
        ] {
            assert!(HeaderText::parse(bad).is_err(), "{bad:?}");
        }
        for ok in [
            "",
            "Einladung: Müller & Söhne",
            "tab\tseparated",
            "日本語の件名",
            &"x".repeat(998),
        ] {
            assert!(HeaderText::parse(ok).is_ok(), "{ok:?}");
        }
    }

    #[test]
    fn header_names_are_tokens() {
        for ok in ["X-Mailer", "Content-Class", "A"] {
            assert!(HeaderName::parse(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "-X",
            "X-",
            "X Mailer",
            "X:Mailer",
            "X\r\nBcc",
            "Ä-Header",
            &"X".repeat(65),
        ] {
            assert!(HeaderName::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn message_ids_have_the_angle_bracket_form() {
        let id = MessageId::parse("<abc.def@Mail.Example.ORG>").unwrap();
        assert_eq!(id.as_str(), "<abc.def@mail.example.org>");
        for bad in [
            "",
            "abc@example.org",
            "<abc>",
            "<@example.org>",
            "<a b@example.org>",
            "<a@>",
            "<a@exa mple.org>",
            "<a\r\n@example.org>",
            "<a@example.org> ",
        ] {
            assert!(MessageId::parse(bad).is_err(), "{bad:?}");
        }
        let outbox = OutboxId::from_uuid(uuid::Uuid::from_u128(5));
        let domain = DomainName::parse("Mail.Example.org").unwrap();
        let derived = MessageId::for_outbox(outbox, &domain);
        assert_eq!(
            derived.as_str(),
            "<00000000-0000-0000-0000-000000000005@mail.example.org>"
        );
        assert_eq!(MessageId::parse(derived.as_str()).unwrap(), derived);
        assert_eq!(MessageId::for_outbox(outbox, &domain), derived, "retries reuse the id");
    }

    #[test]
    fn media_types_are_normalized() {
        assert_eq!(MediaType::parse("Application/ICS").unwrap().as_str(), "application/ics");
        for bad in [
            "",
            "text",
            "text/",
            "/plain",
            "text/plain; charset=utf-8",
            "a/b/c",
            "te xt/plain",
        ] {
            assert!(MediaType::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_composed_mail_validates() {
        mail().validate().unwrap();
        let message = mail();
        let recipients: Vec<&str> = message.recipients().map(Email::as_str).collect();
        assert_eq!(recipients, vec!["guest@example.net"]);
    }

    #[test]
    fn validation_rejects_missing_recipients_and_reserved_headers() {
        let mut none = mail();
        none.to.clear();
        assert_eq!(none.validate(), Err(MailError::NoRecipient));

        let mut many = mail();
        many.to = (0..=MAX_RECIPIENTS)
            .map(|i| Mailbox::bare(email(&format!("u{i}@example.net"))))
            .collect();
        assert_eq!(many.validate(), Err(MailError::TooManyRecipients));

        for reserved in [
            "Subject",
            "FROM",
            "message-id",
            "Content-Type",
            "bcc",
            "MIME-Version",
            "Reply-To",
            "Date",
        ] {
            let mut bad = mail();
            bad.headers.push(ExtraHeader {
                name: HeaderName::parse(reserved).unwrap(),
                value: HeaderText::parse("x").unwrap(),
            });
            assert_eq!(
                bad.validate(),
                Err(MailError::ReservedHeader(reserved.to_owned())),
                "{reserved}"
            );
        }
    }

    #[test]
    fn serde_validates_headers_on_the_way_in() {
        let json = serde_json::to_string(&mail()).unwrap();
        let back: OutgoingMail = serde_json::from_str(&json).unwrap();
        assert_eq!(back, mail());
        let tampered = json.replace("Einladung: Teamtreffen", "x\\r\\nBcc: evil@example.net");
        assert!(serde_json::from_str::<OutgoingMail>(&tampered).is_err());
    }

    #[test]
    fn mailboxes() {
        let bare = Mailbox::bare(email("a@example.org"));
        assert_eq!(bare.name, None);
        let named = Mailbox::named(HeaderText::parse("A").unwrap(), email("a@example.org"));
        assert_eq!(named.name.as_ref().map(HeaderText::as_str), Some("A"));
        assert_eq!(named.address, bare.address);
    }
}
