use serde_json::json;

use super::*;

fn event(value: Value) -> EventData {
    serde_json::from_value(value).unwrap()
}

fn berlin() -> TimeZoneName {
    TimeZoneName::parse("Europe/Berlin").unwrap()
}

fn model(value: Value) -> Value {
    event_model(&event(value), berlin()).unwrap()
}

#[test]
fn a_timed_event_in_a_zone_keeps_its_wall_clock_and_names_the_zone() {
    let model = model(json!({
        "summary": "  Planning ",
        "description": "Agenda",
        "location": "Room 4",
        "start": {"date_time": "2027-01-12T10:00:00", "time_zone": "Europe/Berlin"},
        "end": {"date_time": "2027-01-12T11:30:00", "time_zone": "Europe/Berlin"}
    }));
    assert_eq!(
        model,
        json!({
            "summary": "Planning",
            "description": "Agenda",
            "location": "Room 4",
            "start": {"date": "2027-01-12", "time": "10:00", "zone": "Europe/Berlin"},
            "end": {"date": "2027-01-12", "time": "11:30", "zone": "Europe/Berlin"},
            "all_day": false,
            "recurring": false
        })
    );
}

#[test]
fn a_duration_is_added_to_the_start() {
    let model = model(json!({
        "summary": "x",
        "start": {"date_time": "2027-01-12T10:00:00", "time_zone": "Europe/Berlin"},
        "duration": "PT1H30M"
    }));
    assert_eq!(
        model["end"],
        json!({"date": "2027-01-12", "time": "11:30", "zone": "Europe/Berlin"})
    );

    let overnight = self::model(json!({
        "summary": "x",
        "start": {"date_time": "2027-01-12T23:00:00", "time_zone": "Europe/Berlin"},
        "duration": "PT2H"
    }));
    assert_eq!(overnight["end"]["date"], "2027-01-13");
    assert_eq!(overnight["end"]["time"], "01:00");
}

#[test]
fn a_duration_is_exact_across_a_daylight_saving_change() {
    // 01:30 CET plus one hour is 03:30 CEST: the clocks skip 02:00 to 03:00 on 2027-03-28.
    let model = model(json!({
        "summary": "x",
        "start": {"date_time": "2027-03-28T01:30:00", "time_zone": "Europe/Berlin"},
        "duration": "PT1H"
    }));
    assert_eq!(model["end"]["time"], "03:30");
}

#[test]
fn utc_instants_are_shown_in_the_zone_of_the_tenant() {
    let model = model(json!({
        "summary": "x",
        "start": {"date_time": "2027-01-12T09:00:00Z"},
        "end": {"date_time": "2027-01-12T10:00:00Z"}
    }));
    assert_eq!(
        model["start"],
        json!({"date": "2027-01-12", "time": "10:00", "zone": "Europe/Berlin"})
    );
    assert_eq!(
        model["end"],
        json!({"date": "2027-01-12", "time": "11:00", "zone": "Europe/Berlin"})
    );
    let summer = self::model(json!({
        "summary": "x",
        "start": {"date_time": "2027-07-12T09:00:00Z"},
        "duration": "PT1H"
    }));
    assert_eq!(summer["start"]["time"], "11:00", "daylight saving time applies");
    assert_eq!(summer["end"]["time"], "12:00");

    let utc = event_model(
        &event(json!({"summary": "x", "start": {"date_time": "2027-01-12T09:00:00Z"}})),
        TimeZoneName::utc(),
    )
    .unwrap();
    assert_eq!(
        utc["start"],
        json!({"date": "2027-01-12", "time": "09:00", "zone": "UTC"})
    );
}

#[test]
fn floating_times_name_no_zone() {
    let model = model(json!({
        "summary": "x",
        "start": {"date_time": "2027-01-12T10:00:00"},
        "duration": "PT45M"
    }));
    assert_eq!(
        model["start"],
        json!({"date": "2027-01-12", "time": "10:00", "zone": null})
    );
    assert_eq!(
        model["end"],
        json!({"date": "2027-01-12", "time": "10:45", "zone": null})
    );
}

#[test]
fn a_timed_event_without_end_has_none() {
    let model = model(json!({"summary": "x", "start": {"date_time": "2027-01-12T10:00:00", "time_zone": "UTC"}}));
    assert_eq!(model["end"], Value::Null);
    assert_eq!(model["all_day"], false);
}

#[test]
fn all_day_events_end_on_their_last_day() {
    let single_by_default = model(json!({"summary": "x", "start": {"date": "2027-01-12"}}));
    assert_eq!(
        single_by_default["start"],
        json!({"date": "2027-01-12", "time": null, "zone": null})
    );
    assert_eq!(
        (single_by_default["end"].clone(), single_by_default["all_day"].clone()),
        (Value::Null, json!(true))
    );

    // DTEND of an all-day event is the day after the last one.
    let single = self::model(json!({"summary": "x", "start": {"date": "2027-01-12"}, "end": {"date": "2027-01-13"}}));
    assert_eq!(single["end"], Value::Null);
    let three_days =
        self::model(json!({"summary": "x", "start": {"date": "2027-01-12"}, "end": {"date": "2027-01-15"}}));
    assert_eq!(
        three_days["end"],
        json!({"date": "2027-01-14", "time": null, "zone": null})
    );
    let by_duration = self::model(json!({"summary": "x", "start": {"date": "2027-01-12"}, "duration": "P2D"}));
    assert_eq!(
        by_duration["end"],
        json!({"date": "2027-01-13", "time": null, "zone": null})
    );
    let one_day = self::model(json!({"summary": "x", "start": {"date": "2027-01-12"}, "duration": "P1D"}));
    assert_eq!(one_day["end"], Value::Null);
}

#[test]
fn optional_texts_are_null_when_blank() {
    let model = model(json!({
        "summary": "x",
        "description": "   ",
        "location": "",
        "start": {"date": "2027-01-12"}
    }));
    assert_eq!(model["description"], Value::Null);
    assert_eq!(model["location"], Value::Null);
    let bare = self::model(json!({"start": {"date": "2027-01-12"}}));
    assert_eq!(bare["summary"], "");
    assert_eq!(bare["description"], Value::Null);
}

#[test]
fn long_descriptions_are_cut() {
    let model = model(json!({
        "summary": "x",
        "description": "ü".repeat(5000),
        "start": {"date": "2027-01-12"}
    }));
    let description = model["description"].as_str().unwrap();
    assert_eq!(description.chars().count(), MAX_DESCRIPTION_CHARS + 1);
    assert!(description.ends_with('…'));
}

#[test]
fn long_summaries_and_locations_are_cut_like_descriptions() {
    let model = model(json!({
        "summary": "s".repeat(70_000),
        "location": "l".repeat(70_000),
        "start": {"date": "2027-01-12"}
    }));
    for key in ["summary", "location"] {
        let value = model[key].as_str().unwrap();
        assert_eq!(value.chars().count(), MAX_SUMMARY_CHARS + 1, "{key}");
        assert!(value.ends_with('…'), "{key}");
    }
}

#[test]
fn replies_keep_a_trimmed_comment_of_at_most_five_hundred_characters() {
    assert_eq!(Reply::new("DECLINED", None).comment, None);
    assert_eq!(Reply::new("DECLINED", Some("  \n ")).comment, None);
    let reply = Reply::new("ACCEPTED", Some("  See you there  "));
    assert_eq!(
        (reply.partstat.as_str(), reply.comment.as_deref()),
        ("ACCEPTED", Some("See you there"))
    );
    let long = Reply::new("TENTATIVE", Some(&"x".repeat(900))).comment.unwrap();
    assert_eq!(long.chars().count(), MAX_COMMENT_CHARS + 1);
    assert!(long.ends_with('…'));
}

#[test]
fn recurrence_is_reported_for_rules_and_extra_dates() {
    let rule = model(json!({
        "summary": "x",
        "start": {"date": "2027-01-12"},
        "recurrence": {"rrule": "FREQ=WEEKLY"}
    }));
    assert_eq!(rule["recurring"], true);
    let dates = self::model(json!({
        "summary": "x",
        "start": {"date": "2027-01-12"},
        "recurrence": {"rdates": [{"date": "2027-02-01"}]}
    }));
    assert_eq!(dates["recurring"], true);
    let only_exclusions = self::model(json!({
        "summary": "x",
        "start": {"date": "2027-01-12"},
        "recurrence": {"exdates": [{"date": "2027-02-01"}]}
    }));
    assert_eq!(only_exclusions["recurring"], false);
    let none = self::model(json!({"summary": "x", "start": {"date": "2027-01-12"}}));
    assert_eq!(none["recurring"], false);
}

#[test]
fn an_event_without_start_cannot_be_described() {
    let error = event_model(&event(json!({"summary": "x"})), berlin()).unwrap_err();
    assert_eq!(error, ModelError::NoStart);
}

#[test]
fn mail_models_always_carry_every_member() {
    let organizer = Person {
        name: Some("Anna Example".to_owned()),
        email: Some("anna@example.org".to_owned()),
    };
    let attendee = Person {
        name: None,
        email: Some("guest@example.net".to_owned()),
    };
    let event = model(json!({"summary": "x", "start": {"date": "2027-01-12"}}));
    let request = MailModel {
        tenant: "Example Organisation",
        organizer: &organizer,
        attendee: &attendee,
        event: event.clone(),
        update: true,
        rsvp_url: Some("https://calendar.example.org/rsvp/dvh_rsvp_x"),
        reply: None,
        reply_to: Some("anna@example.org"),
    }
    .to_value();
    assert_eq!(
        request,
        json!({
            "tenant": {"name": "Example Organisation"},
            "organizer": {"name": "Anna Example", "email": "anna@example.org"},
            "attendee": {"name": null, "email": "guest@example.net"},
            "event": event,
            "update": true,
            "rsvp_url": "https://calendar.example.org/rsvp/dvh_rsvp_x",
            "reply": null,
            "reply_to": "anna@example.org"
        })
    );

    let nameless = Person {
        name: None,
        email: Some("anna@example.org".to_owned()),
    };
    let nobody = Person::default();
    let reply = Reply {
        partstat: "ACCEPTED".to_owned(),
        comment: Some("See you".to_owned()),
    };
    let answered = MailModel {
        tenant: "T",
        organizer: &nameless,
        attendee: &nobody,
        event,
        update: false,
        rsvp_url: None,
        reply: Some(&reply),
        reply_to: None,
    }
    .to_value();
    assert_eq!(
        answered["organizer"],
        json!({"name": "anna@example.org", "email": "anna@example.org"})
    );
    assert_eq!(answered["attendee"], json!({"name": null, "email": null}));
    assert_eq!(answered["rsvp_url"], Value::Null);
    assert_eq!(answered["reply_to"], Value::Null, "a mail nobody can reply to says so");
    assert_eq!(answered["reply"], json!({"partstat": "ACCEPTED", "comment": "See you"}));
    let unnamed = MailModel {
        organizer: &nobody,
        ..MailModel {
            tenant: "T",
            organizer: &nobody,
            attendee: &nobody,
            event: Value::Null,
            update: false,
            rsvp_url: None,
            reply: None,
            reply_to: None,
        }
    }
    .to_value();
    assert_eq!(
        unnamed["organizer"]["name"], "",
        "the organizer is always addressed by a string"
    );
}
