//! The models the mail templates are rendered with.
//!
//! The shape is the contract between the composer and the themes (`docs/templates.md`, and
//! `davhaven_templates::catalog` for the samples every theme is checked against). Optional parts are always
//! present and `null` when absent, so a template can test them under strict undefined behavior.
//!
//! ```json
//! {
//!   "tenant":    { "name": "Example Organisation" },
//!   "organizer": { "name": "Anna Example", "email": "anna@example.org" },
//!   "attendee":  { "name": "Guest Example", "email": "guest@example.net" },
//!   "event": {
//!     "summary": "…", "description": "…", "location": "…",
//!     "start": { "date": "2027-01-12", "time": "10:00", "zone": "Europe/Berlin" },
//!     "end":   { "date": "2027-01-12", "time": "11:30", "zone": "Europe/Berlin" },
//!     "all_day": false, "recurring": false
//!   },
//!   "update": false,
//!   "rsvp_url": "https://calendar.example.org/rsvp/dvh_rsvp_…",
//!   "reply": null,
//!   "reply_to": "anna@example.org"
//! }
//! ```

use chrono::{Duration, NaiveDate, NaiveDateTime, TimeZone};
use davhaven_domain::{EventData, EventTime, TimeZoneName};
use serde_json::{Value, json};

/// The longest description a mail carries, in characters; longer ones are cut and end in an ellipsis.
const MAX_DESCRIPTION_CHARS: usize = 4000;

/// The longest summary and location a mail carries, in characters (an iCalendar value can be 64 KiB).
const MAX_SUMMARY_CHARS: usize = 300;

/// The longest comment of an answer a mail carries, in characters (the limit of the RSVP page and of the organizer's copy).
pub(crate) const MAX_COMMENT_CHARS: usize = davhaven_ical::itip::MAX_COMMENT_CHARS;

/// Why an event cannot be described.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ModelError {
    /// The event has no start, so no mail can say when it takes place.
    #[error("the event has no start")]
    NoStart,
}

/// A person named in a mail.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Person {
    /// The display name, when known.
    pub(crate) name: Option<String>,
    /// The e-mail address, when the person has one.
    pub(crate) email: Option<String>,
}

impl Person {
    /// The name, or the address, or nothing: what to call the person in a sentence.
    pub(crate) fn label(&self) -> &str {
        self.name.as_deref().or(self.email.as_deref()).unwrap_or_default()
    }

    /// The model of a person whose name the template may leave out (it falls back to the address).
    fn optional(&self) -> Value {
        json!({ "name": self.name, "email": self.email })
    }

    /// The model of a person the template addresses by name: the name is never `null`, it falls back to the
    /// address and finally to the empty string.
    fn named(&self) -> Value {
        json!({ "name": self.label(), "email": self.email })
    }
}

/// What the mail says about the answer of an attendee (`imip_reply`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reply {
    /// The `PARTSTAT` as iCalendar spells it.
    pub(crate) partstat: String,
    /// The comment of the attendee, if the reply carries one (cut to [`MAX_COMMENT_CHARS`]).
    pub(crate) comment: Option<String>,
}

impl Reply {
    /// The answer `partstat` with the attendee's `comment`: blank comments are dropped and long ones are cut.
    pub(crate) fn new(partstat: &str, comment: Option<&str>) -> Self {
        Self {
            partstat: partstat.to_owned(),
            comment: clean_comment(comment),
        }
    }
}

/// The remark of an attendee as the mail says it and as the `COMMENT` of the reply carries it: blank remarks are
/// dropped and long ones are cut.
pub(crate) fn clean_comment(comment: Option<&str>) -> Option<String> {
    text(comment).map(|comment| shorten(comment, MAX_COMMENT_CHARS))
}

/// Everything a mail model is made of.
pub(crate) struct MailModel<'a> {
    /// The display name of the tenant.
    pub(crate) tenant: &'a str,
    /// The organizer of the event.
    pub(crate) organizer: &'a Person,
    /// The attendee the mail is about.
    pub(crate) attendee: &'a Person,
    /// The event.
    pub(crate) event: Value,
    /// Whether the mail updates an invitation sent earlier.
    pub(crate) update: bool,
    /// The link to the RSVP page, for invitations.
    pub(crate) rsvp_url: Option<&'a str>,
    /// The answer, for replies.
    pub(crate) reply: Option<&'a Reply>,
    /// The address a reply to the mail reaches a person at: the `Reply-To` of a mail sent in the service form, or the
    /// `From` of a mail sent in the name of the person. `None` when the mail comes from the no-reply address of the tenant
    /// (the person has no e-mail address, as a service account), so a footer can tell the reader not to reply.
    pub(crate) reply_to: Option<&'a str>,
}

impl MailModel<'_> {
    /// The JSON model.
    pub(crate) fn to_value(&self) -> Value {
        json!({
            "tenant": { "name": self.tenant },
            "organizer": self.organizer.named(),
            "attendee": self.attendee.optional(),
            "event": self.event,
            "update": self.update,
            "rsvp_url": self.rsvp_url,
            "reply": self.reply.map(|reply| json!({ "partstat": reply.partstat, "comment": reply.comment })),
            "reply_to": self.reply_to,
        })
    }
}

fn text(value: Option<&str>) -> Option<String> {
    value.map(str::trim).filter(|text| !text.is_empty()).map(str::to_owned)
}

/// `text` cut to `max` characters, with an ellipsis when something was cut.
fn shorten(text: String, max: usize) -> String {
    if text.chars().count() <= max {
        return text;
    }
    let mut cut: String = text.chars().take(max).collect();
    cut.push('…');
    cut
}

fn moment(local: NaiveDateTime, zone: Option<&str>) -> Value {
    json!({
        "date": local.format("%Y-%m-%d").to_string(),
        "time": local.format("%H:%M").to_string(),
        "zone": zone,
    })
}

fn day(date: NaiveDate) -> Value {
    json!({ "date": date.format("%Y-%m-%d").to_string(), "time": null, "zone": null })
}

/// The wall-clock time of a point of an event as the mail shows it, and the zone to name next to it. UTC
/// instants are shown in `display_zone`, floating times as they are (they mean the same wherever the reader is).
fn wall_clock(time: &EventTime, display_zone: TimeZoneName) -> Option<(NaiveDateTime, Option<String>)> {
    match time {
        EventTime::Date(date) => date.and_hms_opt(0, 0, 0).map(|local| (local, None)),
        EventTime::Floating(local) => Some((*local, None)),
        EventTime::Zoned { local, zone } => Some((*local, Some(zone.as_str().to_owned()))),
        EventTime::Utc(instant) => Some((
            instant.with_timezone(&display_zone.tz()).naive_local(),
            Some(display_zone.as_str().to_owned()),
        )),
    }
}

/// The end of a timed event: `DTEND` as written, or the start plus `DURATION` (an exact duration, so a daylight
/// saving transition in between moves the wall-clock end).
fn timed_end(event: &EventData, start: &EventTime, display_zone: TimeZoneName) -> Option<Value> {
    if let Some(end) = &event.end {
        let (local, zone) = wall_clock(end, display_zone)?;
        return Some(moment(local, zone.as_deref()));
    }
    let seconds = event.duration.as_ref()?.seconds();
    let by = Duration::try_seconds(seconds)?;
    match start {
        EventTime::Zoned { local, zone } => {
            let begin = zone.tz().from_local_datetime(local).earliest()?;
            let finish = begin.checked_add_signed(by)?;
            Some(moment(finish.naive_local(), Some(zone.as_str())))
        }
        EventTime::Floating(local) => Some(moment(local.checked_add_signed(by)?, None)),
        EventTime::Utc(instant) => {
            let finish = instant.checked_add_signed(by)?.with_timezone(&display_zone.tz());
            Some(moment(finish.naive_local(), Some(display_zone.as_str())))
        }
        EventTime::Date(_) => None,
    }
}

/// The last day of an all-day event, inclusive, when it is later than the first one. `DTEND` of an all-day
/// event is exclusive in iCalendar; the templates take the last day itself.
fn all_day_end(event: &EventData, first: NaiveDate) -> Option<Value> {
    let last = match (&event.end, &event.duration) {
        (Some(EventTime::Date(end)), _) => end.pred_opt()?,
        (Some(other), _) => wall_clock(other, TimeZoneName::utc())?.0.date(),
        (None, Some(duration)) => {
            let days = duration.seconds().checked_div(86_400)?;
            first.checked_add_signed(Duration::try_days(days)?)?.pred_opt()?
        }
        (None, None) => first,
    };
    (last > first).then(|| day(last))
}

/// The `event` part of a mail model.
///
/// # Errors
///
/// [`ModelError::NoStart`] when the event has no start.
pub(crate) fn event_model(event: &EventData, display_zone: TimeZoneName) -> Result<Value, ModelError> {
    let start = event.start.as_ref().ok_or(ModelError::NoStart)?;
    let (start_value, end_value, all_day) = if let EventTime::Date(first) = start {
        (day(*first), all_day_end(event, *first), true)
    } else {
        let (local, zone) = wall_clock(start, display_zone).ok_or(ModelError::NoStart)?;
        (
            moment(local, zone.as_deref()),
            timed_end(event, start, display_zone),
            false,
        )
    };
    let recurring = event
        .recurrence
        .as_ref()
        .is_some_and(|recurrence| recurrence.rrule.is_some() || !recurrence.rdates.is_empty());
    Ok(json!({
        "summary": shorten(event.summary.as_deref().map(str::trim).unwrap_or_default().to_owned(), MAX_SUMMARY_CHARS),
        "description": text(event.description.as_deref()).map(|text| shorten(text, MAX_DESCRIPTION_CHARS)),
        "location": text(event.location.as_deref()).map(|text| shorten(text, MAX_SUMMARY_CHARS)),
        "start": start_value,
        "end": end_value,
        "all_day": all_day,
        "recurring": recurring,
    }))
}

#[cfg(test)]
mod tests;
