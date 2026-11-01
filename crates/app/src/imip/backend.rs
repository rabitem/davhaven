//! The seam between the composer and the iCalendar layer.
//!
//! The composer needs two things from the calendar data of a message: the event it is about (to fill the template
//! and to name organizer and attendee) and the iTIP text that goes into the `text/calendar` part. [`IcalBackend`]
//! gets both from `davhaven-ical` on a blocking thread under the wall-clock budget of the iCalendar limits; tests
//! of the composer use a double and need no calendar parser. The webhook fan-out reads the summary of an object
//! through the same seam ([`CalendarBackend::describe`]), so that no adapter ever parses iCalendar text.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use davhaven_domain::{AddressKind, CalendarUserAddress, EventData, IcalLimits, ItipMethod};
use davhaven_ical::IcalError;
use davhaven_ical::itip::{AttendeeVisibility, MessageScope, MessageSpec, rewrite_addresses};
use davhaven_ical::parse::ParsedCalendar;

/// An iTIP message and the event it is about.
#[derive(Debug, Clone, PartialEq)]
pub struct Prepared {
    /// The master component as the JSON event model, for the template and for naming the people.
    pub event: EventData,
    /// The iTIP message as iCalendar text: `METHOD`, the components of the event for this recipient, a
    /// `VTIMEZONE` for every `TZID`; alarms, `X-APPLE-*`, `X-MOZ-*`, `SCHEDULE-*` and binary attachments removed.
    pub ics: String,
}

/// What to build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRequest {
    /// The method of the message.
    pub method: ItipMethod,
    /// The recipient of the message (the attendee of a `REQUEST` or `CANCEL`, the organizer of a `REPLY`).
    pub recipient: CalendarUserAddress,
    /// For a `REPLY`: the attendee who answers.
    pub replying_attendee: Option<CalendarUserAddress>,
    /// For a `REPLY`: the remark of the attendee (already cleaned and cut by the composer), written as `COMMENT`.
    pub comment: Option<String>,
    /// The `DTSTAMP` of the message. It is the moment the job was queued and not the time of the send, so that a
    /// retry builds the same message, and a `CANCEL` queued after a `REQUEST` is never older than it
    /// (RFC 5546 section 2.1.5 orders messages of equal `SEQUENCE` by `DTSTAMP`).
    pub dtstamp: DateTime<Utc>,
    /// The mail address that names the organizer in a `REQUEST` or `CANCEL` whose organizer has none of its own: the
    /// calendar user address of such an organizer (a service account) is an `urn:uuid` or a principal URL, which no mail
    /// client of a guest can use. The address the mail comes from (the tenant's sender address) takes its place, and the
    /// `CN` of the organizer stays. `None` leaves the organizer as it is; the handler gives none for a `REPLY`.
    pub stand_in_organizer: Option<CalendarUserAddress>,
}

/// Why a message cannot be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackendError {
    /// The calendar data cannot become this message; repeating does not help.
    #[error("the calendar data cannot be turned into this message: {0}")]
    Invalid(String),
    /// The calendar layer cannot do it right now (not implemented in this build, or its worker failed).
    #[error("the calendar layer is not available: {0}")]
    Unavailable(String),
}

/// Reads calendar data and builds iTIP messages.
#[async_trait]
pub trait CalendarBackend: Send + Sync {
    /// Reads `source` (iCalendar text) and builds the message described by `request` from it.
    ///
    /// # Errors
    ///
    /// [`BackendError::Invalid`] when the data is not usable for this message, [`BackendError::Unavailable`] when
    /// the calendar layer cannot run.
    async fn prepare(&self, source: &str, request: &MessageRequest) -> Result<Prepared, BackendError>;

    /// Reads `source` (iCalendar text) and describes its master component as the JSON event model (webhook
    /// details need the summary).
    ///
    /// # Errors
    ///
    /// [`BackendError::Invalid`] when the data is not usable, [`BackendError::Unavailable`] when the calendar
    /// layer cannot run (and for backends that do not offer this).
    async fn describe(&self, _source: &str) -> Result<EventData, BackendError> {
        Err(BackendError::Unavailable(
            "this calendar backend cannot describe events".to_owned(),
        ))
    }
}

/// The production backend: `davhaven-ical`.
#[derive(Debug, Clone)]
pub struct IcalBackend {
    limits: IcalLimits,
}

impl IcalBackend {
    /// Creates the backend with the iCalendar limits of the application.
    pub fn new(limits: IcalLimits) -> Self {
        Self { limits }
    }
}

fn from_ical(error: IcalError) -> BackendError {
    // A limit that depends on the load of the machine (the time budget) says nothing about the data.
    if error.is_transient() {
        return BackendError::Unavailable("the calendar layer ran out of time".to_owned());
    }
    match error {
        IcalError::Invalid(message) | IcalError::ObjectRule(message) | IcalError::OrganizerMismatch(message) => {
            BackendError::Invalid(message)
        }
        IcalError::Limit(kind) => BackendError::Invalid(format!("the limit `{kind}` is exceeded")),
        IcalError::Unsupported(what) => BackendError::Unavailable(what),
        // The layer grows new kinds of rejection; none of them can be repaired by repeating the call.
        other => BackendError::Invalid(other.to_string()),
    }
}

/// The blocking part of [`CalendarBackend::describe`]: parse and read the master component.
fn describe_blocking(source: &str, limits: &IcalLimits) -> Result<EventData, IcalError> {
    let calendar = davhaven_ical::parse::parse(source.as_bytes(), limits)?;
    davhaven_ical::merge::to_event_data(&calendar, None)
}

/// The calendar with the organizer named by the stand-in address, when the request has one and the organizer's own address is
/// not a mail address (the organizer has none: what the server could map to a `mailto` it already did). The caller asks for it
/// in the messages of the organizer (`REQUEST`, `CANCEL`) only: the organizer of a `REPLY` is the recipient, who is somebody
/// else's.
fn with_stand_in_organizer(
    calendar: ParsedCalendar,
    event: &EventData,
    request: &MessageRequest,
) -> Result<ParsedCalendar, IcalError> {
    let (Some(stand_in), Some(organizer)) = (&request.stand_in_organizer, &event.organizer) else {
        return Ok(calendar);
    };
    if organizer.address.kind() == AddressKind::Mailto {
        return Ok(calendar);
    }
    rewrite_addresses(&calendar, &|address| {
        (address == &organizer.address).then(|| stand_in.clone())
    })
}

/// The blocking part: parse, describe, build, serialize.
fn prepare_blocking(source: &str, request: &MessageRequest, limits: &IcalLimits) -> Result<Prepared, IcalError> {
    let calendar = davhaven_ical::parse::parse(source.as_bytes(), limits)?;
    let event = davhaven_ical::merge::to_event_data(&calendar, None)?;
    let calendar = with_stand_in_organizer(calendar, &event, request)?;
    let message = davhaven_ical::itip::build_message(
        &calendar,
        &MessageSpec {
            method: request.method,
            recipient: request.recipient.clone(),
            replying_attendee: request.replying_attendee.clone(),
            scope: MessageScope::Whole,
            dtstamp: request.dtstamp,
            // Guests learn nothing about who else is invited (`docs/interop.md`); the mail says the same.
            attendees: AttendeeVisibility::Own,
            comment: request.comment.clone(),
        },
    )?;
    let ics = davhaven_ical::serialize::serialize(&message.calendar)?;
    Ok(Prepared { event, ics })
}

impl IcalBackend {
    /// Runs `work` on a blocking thread under the wall-clock budget.
    ///
    /// The iCalendar layer enforces `time_budget_ms` itself; the timeout out here waits twice as long, so that
    /// data that is too expensive is reported by the parser (permanent) and only a stuck worker is a timeout.
    async fn blocking<T, F>(&self, work: F) -> Result<T, BackendError>
    where
        T: Send + 'static,
        F: FnOnce(&IcalLimits) -> Result<T, IcalError> + Send + 'static,
    {
        let limits = self.limits.clone();
        let budget = Duration::from_millis(limits.time_budget_ms).saturating_mul(2);
        let job = tokio::task::spawn_blocking(move || work(&limits));
        match tokio::time::timeout(budget, job).await {
            Ok(Ok(result)) => result.map_err(from_ical),
            Ok(Err(_join)) => Err(BackendError::Unavailable("the calendar worker failed".to_owned())),
            // A busy host can take longer than the budget with perfectly valid data, and the blocking task cannot
            // be cancelled: a retryable condition of the host, not of the data.
            Err(_elapsed) => Err(BackendError::Unavailable(
                "the calendar worker did not finish in time".to_owned(),
            )),
        }
    }
}

#[async_trait]
impl CalendarBackend for IcalBackend {
    async fn prepare(&self, source: &str, request: &MessageRequest) -> Result<Prepared, BackendError> {
        let source = source.to_owned();
        let request = request.clone();
        self.blocking(move |limits| prepare_blocking(&source, &request, limits))
            .await
    }

    async fn describe(&self, source: &str) -> Result<EventData, BackendError> {
        let source = source.to_owned();
        self.blocking(move |limits| describe_blocking(&source, limits)).await
    }
}

#[cfg(test)]
mod tests {
    use davhaven_ical::LimitKind;

    use super::*;

    fn request() -> MessageRequest {
        MessageRequest {
            method: ItipMethod::Request,
            recipient: CalendarUserAddress::parse("mailto:guest@example.net").unwrap(),
            replying_attendee: None,
            comment: None,
            dtstamp: DateTime::UNIX_EPOCH,
            stand_in_organizer: None,
        }
    }

    #[test]
    fn ical_errors_keep_their_meaning() {
        assert_eq!(
            from_ical(IcalError::invalid("no VEVENT")),
            BackendError::Invalid("no VEVENT".to_owned())
        );
        assert_eq!(
            from_ical(IcalError::Limit(LimitKind::Attendees)),
            BackendError::Invalid(format!("the limit `{}` is exceeded", LimitKind::Attendees))
        );
        assert_eq!(
            from_ical(IcalError::unsupported("build_message")),
            BackendError::Unavailable("build_message".to_owned())
        );
        assert_eq!(
            from_ical(IcalError::object_rule("two UIDs")),
            BackendError::Invalid("two UIDs".to_owned())
        );
        assert_eq!(
            from_ical(IcalError::organizer_mismatch("two organizers")),
            BackendError::Invalid("two organizers".to_owned())
        );
        assert!(
            matches!(
                from_ical(IcalError::Limit(LimitKind::TimeBudget)),
                BackendError::Unavailable(_)
            ),
            "running out of time is the machine's problem, not the data's"
        );
    }

    /// An event of a service account: its organizer is known by an `urn:uuid`, there is no mail address to name.
    fn event_of(organizer: &str) -> String {
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Example//Test//EN\r\nBEGIN:VEVENT\r\nUID:u1\r\n\
             DTSTAMP:20270101T000000Z\r\nDTSTART:20270201T100000Z\r\nDTEND:20270201T110000Z\r\nSUMMARY:Course\r\n\
             ORGANIZER;CN=Course plan:{organizer}\r\nATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:guest@example.net\r\n\
             END:VEVENT\r\nEND:VCALENDAR\r\n"
        )
    }

    fn stand_in() -> CalendarUserAddress {
        CalendarUserAddress::parse("mailto:noreply@mail.example.org").unwrap()
    }

    #[tokio::test]
    async fn an_organizer_without_a_mail_address_is_named_by_the_address_the_mail_comes_from() {
        let backend = IcalBackend::new(IcalLimits::default());
        let urn = event_of("urn:uuid:018f3c1e-7b2a-7c3d-9e4f-0123456789ab");
        for method in [ItipMethod::Request, ItipMethod::Cancel] {
            let request = MessageRequest {
                method,
                stand_in_organizer: Some(stand_in()),
                ..request()
            };
            let prepared = backend.prepare(&urn, &request).await.unwrap();
            assert!(
                prepared.ics.contains("mailto:noreply@mail.example.org"),
                "{method:?}: {}",
                prepared.ics
            );
            assert!(!prepared.ics.contains("urn:uuid"), "{method:?}: {}", prepared.ics);
            assert!(
                prepared.ics.contains("Course plan"),
                "the name of the organizer stays: {}",
                prepared.ics
            );
            // The people of the mail are read from the event as it is stored: the organizer is still the principal.
            let organizer = prepared.event.organizer.unwrap();
            assert_eq!(
                organizer.address.as_str(),
                "urn:uuid:018f3c1e-7b2a-7c3d-9e4f-0123456789ab"
            );
        }
        // Without a stand-in the organizer stays as it is.
        let plain = backend.prepare(&urn, &request()).await.unwrap();
        assert!(
            plain.ics.contains("urn:uuid:018f3c1e-7b2a-7c3d-9e4f-0123456789ab"),
            "{}",
            plain.ics
        );
    }

    #[tokio::test]
    async fn an_organizer_with_a_mail_address_is_never_replaced() {
        let backend = IcalBackend::new(IcalLimits::default());
        let mailto = event_of("mailto:anna@example.org");
        let request = MessageRequest {
            stand_in_organizer: Some(stand_in()),
            ..request()
        };
        let prepared = backend.prepare(&mailto, &request).await.unwrap();
        assert!(prepared.ics.contains("mailto:anna@example.org"), "{}", prepared.ics);
        assert!(!prepared.ics.contains("noreply@mail.example.org"), "{}", prepared.ics);
    }

    #[tokio::test]
    async fn data_that_is_not_a_calendar_is_an_error_and_never_a_panic() {
        let backend = IcalBackend::new(IcalLimits::default());
        for source in ["", "garbage", "{0}{1}"] {
            assert!(backend.prepare(source, &request()).await.is_err(), "{source:?}");
        }
    }
}
