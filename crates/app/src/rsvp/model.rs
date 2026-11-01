//! The models of the RSVP pages (`docs/templates.md`: `rsvp_page`, `rsvp_answered`, `rsvp_unavailable`).
//!
//! The pages are served to whoever holds the link, and a link is a bearer credential that can be forwarded. They
//! therefore show what the invitation mail showed to the guest and nothing more: the summary, the time, the
//! location and the name of the organizer. Never the description (it carries dial-in codes and private notes), never
//! the other attendees, never an e-mail address. Optional parts are always present and `null` when absent, so the
//! templates can test them under strict undefined behavior.

use chrono::{Duration, NaiveDate, NaiveDateTime, TimeZone};
use davhaven_domain::{EventData, EventTime, PartStat, TimeZoneName};
use serde_json::{Value, json};

use super::MAX_COMMENT_CHARS;

/// The longest summary and location a page shows, in characters (an iCalendar value can be 64 KiB).
const MAX_TEXT_CHARS: usize = 300;

/// What the pages need to know about the invitation.
#[derive(Debug, Clone)]
pub(super) struct Invitation<'a> {
    /// The name of the tenant the page is served under.
    pub(super) tenant: &'a str,
    /// The name of the organizer, or the empty string when nobody knows it.
    pub(super) organizer: &'a str,
    /// The event.
    pub(super) event: &'a EventData,
    /// The zone UTC instants are shown in.
    pub(super) zone: TimeZoneName,
}

/// `text` trimmed and cut to `max` characters, with an ellipsis when something was cut; blank text is `None`.
fn cut(text: Option<&str>, max: usize) -> Option<String> {
    let text = text.map(str::trim).filter(|text| !text.is_empty())?;
    if text.chars().count() <= max {
        return Some(text.to_owned());
    }
    let mut shortened: String = text.chars().take(max).collect();
    shortened.push('…');
    Some(shortened)
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

/// The wall-clock time of a point of an event and the zone to name next to it: UTC instants are shown in `zone`,
/// floating times as they are.
fn wall_clock(time: &EventTime, zone: TimeZoneName) -> Option<(NaiveDateTime, Option<String>)> {
    match time {
        EventTime::Date(date) => date.and_hms_opt(0, 0, 0).map(|local| (local, None)),
        EventTime::Floating(local) => Some((*local, None)),
        EventTime::Zoned { local, zone } => Some((*local, Some(zone.as_str().to_owned()))),
        EventTime::Utc(instant) => Some((
            instant.with_timezone(&zone.tz()).naive_local(),
            Some(zone.as_str().to_owned()),
        )),
    }
}

/// The end of a timed event: `DTEND`, or the start plus `DURATION`.
fn timed_end(event: &EventData, start: &EventTime, zone: TimeZoneName) -> Option<Value> {
    if let Some(end) = &event.end {
        let (local, name) = wall_clock(end, zone)?;
        return Some(moment(local, name.as_deref()));
    }
    let by = Duration::try_seconds(event.duration.as_ref()?.seconds())?;
    match start {
        EventTime::Zoned { local, zone: own } => {
            let begin = own.tz().from_local_datetime(local).earliest()?;
            let finish = begin.checked_add_signed(by)?;
            Some(moment(finish.naive_local(), Some(own.as_str())))
        }
        EventTime::Floating(local) => Some(moment(local.checked_add_signed(by)?, None)),
        EventTime::Utc(instant) => {
            let finish = instant.checked_add_signed(by)?.with_timezone(&zone.tz());
            Some(moment(finish.naive_local(), Some(zone.as_str())))
        }
        EventTime::Date(_) => None,
    }
}

/// The last day of an all-day event, inclusive, when it is later than the first one (`DTEND` of an all-day event is
/// exclusive in iCalendar; the templates take the last day itself).
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

/// The `event` part of a page model: never with a description. `None` when the event has no start.
pub(super) fn event_model(event: &EventData, zone: TimeZoneName) -> Option<Value> {
    let start = event.start.as_ref()?;
    let (start_value, end_value, all_day) = if let EventTime::Date(first) = start {
        (day(*first), all_day_end(event, *first), true)
    } else {
        let (local, name) = wall_clock(start, zone)?;
        (moment(local, name.as_deref()), timed_end(event, start, zone), false)
    };
    let recurring = event
        .recurrence
        .as_ref()
        .is_some_and(|recurrence| recurrence.rrule.is_some() || !recurrence.rdates.is_empty());
    Some(json!({
        "summary": cut(event.summary.as_deref(), MAX_TEXT_CHARS).unwrap_or_default(),
        "description": null,
        "location": cut(event.location.as_deref(), MAX_TEXT_CHARS),
        "start": start_value,
        "end": end_value,
        "all_day": all_day,
        "recurring": recurring,
    }))
}

impl Invitation<'_> {
    /// The parts both pages share.
    fn base(&self) -> Option<serde_json::Map<String, Value>> {
        let Value::Object(map) = json!({
            "tenant": { "name": self.tenant },
            "event": event_model(self.event, self.zone)?,
            "organizer": { "name": self.organizer },
        }) else {
            return None;
        };
        Some(map)
    }

    /// The model of `rsvp_page`: the invitation and the form. `error` names the notice shown above the form after
    /// a refused answer (`invalid_csrf`, `invalid_answer`, `comment_too_long`).
    pub(super) fn page(&self, cancelled: bool, current: PartStat, csrf: &str, error: Option<&str>) -> Option<Value> {
        let mut model = self.base()?;
        model.insert("cancelled".to_owned(), json!(cancelled));
        model.insert("current".to_owned(), json!(current.as_ical()));
        model.insert("error".to_owned(), error.map_or(Value::Null, |error| json!(error)));
        // The form posts to the address of the page, which is the RSVP link: the application never holds the link.
        model.insert(
            "form".to_owned(),
            json!({ "action": "?", "csrf": csrf, "comment_max": MAX_COMMENT_CHARS }),
        );
        Some(Value::Object(model))
    }

    /// The model of `rsvp_answered`: what was recorded and the way back to change it.
    pub(super) fn answered(&self, answer: PartStat) -> Option<Value> {
        let mut model = self.base()?;
        model.insert("answer".to_owned(), json!(answer.as_ical()));
        model.insert("link".to_owned(), json!("?"));
        Some(Value::Object(model))
    }
}

#[cfg(test)]
mod tests {
    use davhaven_domain::EventDuration;

    use super::*;

    fn event(start: EventTime) -> EventData {
        EventData {
            summary: Some("  Kick-off  ".to_owned()),
            description: Some("dial-in 1234".to_owned()),
            location: Some("Room 1".to_owned()),
            start: Some(start),
            ..EventData::default()
        }
    }

    fn berlin() -> TimeZoneName {
        TimeZoneName::parse("Europe/Berlin").unwrap()
    }

    fn utc(hour: u32) -> EventTime {
        EventTime::Utc(chrono::Utc.with_ymd_and_hms(2027, 1, 12, hour, 0, 0).unwrap())
    }

    #[test]
    fn utc_instants_are_shown_in_the_zone_of_the_tenant_and_the_description_is_never_shown() {
        let mut data = event(utc(9));
        data.end = Some(utc(10));
        let model = event_model(&data, berlin()).unwrap();
        assert_eq!(model["summary"], "Kick-off");
        assert_eq!(model["description"], Value::Null, "the link is a bearer credential");
        assert_eq!(model["location"], "Room 1");
        assert_eq!(
            model["start"],
            json!({"date": "2027-01-12", "time": "10:00", "zone": "Europe/Berlin"})
        );
        assert_eq!(
            model["end"],
            json!({"date": "2027-01-12", "time": "11:00", "zone": "Europe/Berlin"})
        );
        assert_eq!(model["all_day"], false);
        assert_eq!(model["recurring"], false);
    }

    #[test]
    fn a_duration_gives_the_end_and_an_all_day_event_names_its_last_day() {
        let mut timed = event(utc(9));
        timed.duration = Some(EventDuration::parse("PT90M").unwrap());
        assert_eq!(
            event_model(&timed, berlin()).unwrap()["end"],
            json!({"date": "2027-01-12", "time": "11:30", "zone": "Europe/Berlin"})
        );
        let first = NaiveDate::from_ymd_opt(2027, 1, 12).unwrap();
        let mut days = event(EventTime::Date(first));
        days.end = Some(EventTime::Date(NaiveDate::from_ymd_opt(2027, 1, 15).unwrap()));
        let model = event_model(&days, berlin()).unwrap();
        assert_eq!(model["all_day"], true);
        assert_eq!(
            model["start"],
            json!({"date": "2027-01-12", "time": null, "zone": null})
        );
        assert_eq!(model["end"], json!({"date": "2027-01-14", "time": null, "zone": null}));
        let single = event(EventTime::Date(first));
        assert_eq!(event_model(&single, berlin()).unwrap()["end"], Value::Null);
    }

    #[test]
    fn floating_and_zoned_times_keep_their_wall_clock_and_a_duration_is_exact_across_a_clock_change() {
        let local = |day: u32, hour: u32, minute: u32| {
            NaiveDate::from_ymd_opt(2027, 3, day)
                .unwrap()
                .and_hms_opt(hour, minute, 0)
                .unwrap()
        };
        let mut floating = event(EventTime::Floating(local(12, 9, 0)));
        floating.duration = Some(EventDuration::parse("PT45M").unwrap());
        let model = event_model(&floating, berlin()).unwrap();
        assert_eq!(
            model["start"],
            json!({"date": "2027-03-12", "time": "09:00", "zone": null}),
            "a floating time is not moved into the zone of the tenant"
        );
        assert_eq!(
            model["end"],
            json!({"date": "2027-03-12", "time": "09:45", "zone": null})
        );
        // Berlin moves from 02:00 CET to 03:00 CEST on 2027-03-28: two hours from 01:30 end at 04:30 on the wall clock.
        let mut zoned = event(EventTime::Zoned {
            local: local(28, 1, 30),
            zone: berlin(),
        });
        zoned.duration = Some(EventDuration::parse("PT2H").unwrap());
        let model = event_model(&zoned, TimeZoneName::utc()).unwrap();
        assert_eq!(
            model["start"],
            json!({"date": "2027-03-28", "time": "01:30", "zone": "Europe/Berlin"}),
            "a zoned time is shown in its own zone, not in the zone of the tenant"
        );
        assert_eq!(
            model["end"],
            json!({"date": "2027-03-28", "time": "04:30", "zone": "Europe/Berlin"})
        );
    }

    #[test]
    fn an_all_day_event_with_a_duration_or_a_timed_end_names_its_last_day() {
        let first = NaiveDate::from_ymd_opt(2027, 1, 12).unwrap();
        let mut days = event(EventTime::Date(first));
        days.duration = Some(EventDuration::parse("P3D").unwrap());
        assert_eq!(
            event_model(&days, berlin()).unwrap()["end"],
            json!({"date": "2027-01-14", "time": null, "zone": null}),
            "three days from the twelfth end with the fourteenth"
        );
        let mut one_day = event(EventTime::Date(first));
        one_day.duration = Some(EventDuration::parse("P1D").unwrap());
        assert_eq!(
            event_model(&one_day, berlin()).unwrap()["end"],
            Value::Null,
            "a single day names no last day"
        );
        let mut timed_end = event(EventTime::Date(first));
        timed_end.end = Some(EventTime::Utc(
            chrono::Utc.with_ymd_and_hms(2027, 1, 14, 12, 0, 0).unwrap(),
        ));
        assert_eq!(
            event_model(&timed_end, berlin()).unwrap()["end"],
            json!({"date": "2027-01-14", "time": null, "zone": null})
        );
    }

    #[test]
    fn an_event_without_a_start_cannot_be_shown_and_long_texts_are_cut() {
        assert!(event_model(&EventData::default(), berlin()).is_none());
        let mut long = event(utc(9));
        long.summary = Some("x".repeat(400));
        let summary = event_model(&long, berlin()).unwrap()["summary"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(summary.chars().count(), MAX_TEXT_CHARS + 1);
        assert!(summary.ends_with('…'));
    }

    #[test]
    fn the_page_and_the_confirmation_carry_what_the_templates_use() {
        let data = event(utc(9));
        let invitation = Invitation {
            tenant: "Acme",
            organizer: "Anna",
            event: &data,
            zone: berlin(),
        };
        let page = invitation.page(false, PartStat::NeedsAction, "v1.token", None).unwrap();
        assert_eq!(page["tenant"]["name"], "Acme");
        assert_eq!(page["organizer"], json!({"name": "Anna"}));
        assert_eq!(page["cancelled"], false);
        assert_eq!(page["current"], "NEEDS-ACTION");
        assert_eq!(page["error"], Value::Null);
        assert_eq!(
            page["form"],
            json!({"action": "?", "csrf": "v1.token", "comment_max": 500})
        );
        let refused = invitation
            .page(false, PartStat::NeedsAction, "v1.fresh", Some("invalid_csrf"))
            .unwrap();
        assert_eq!(refused["error"], "invalid_csrf");
        assert_eq!(refused["form"]["csrf"], "v1.fresh");
        let answered = invitation.answered(PartStat::Tentative).unwrap();
        assert_eq!(answered["answer"], "TENTATIVE");
        assert_eq!(answered["link"], "?");
        assert!(answered.get("form").is_none());
        assert!(
            !page.to_string().contains("dial-in"),
            "nothing of the description reaches the page: {page}"
        );
    }
}
