//! What an MCP caller may see of an event: the busy form of what is private to others (PLAN 2.12, 2.13).
//!
//! An assistant reads calendars on behalf of a person, and what it reads goes to the provider of the model. A calendar that
//! is shared with the person may hold events the person is not meant to read: an event of class `PRIVATE` or
//! `CONFIDENTIAL` in a calendar the person does not own is, for them, the time it blocks and nothing else. That is the rule
//! of the subscription feeds ([`crate::authz::busy_only`]: the class is restricted and the reader is not the owner of
//! the calendar) applied to MCP; DAV and the management API show the person's own clients everything the person may read.
//! MCP also looks at the class of an instance: an override that says `CLASS:PRIVATE` inside a public series is private,
//! and an override that leaves the class out does not make a private series public.
//!
//! The rule is the application's, not the protocol layer's (PLAN 2.6: protocol crates never decide), because it has to hold
//! in three places that only the application reaches:
//!
//! * **What an answer shows.** Every view of an event that [`Linker::view`](super::events::Linker::view) builds for a
//!   caller that reads through MCP in a calendar it does not own is the [busy form](busy_form) when [`hides`] says so: the
//!   time, the recurrence, the status and the classification, a UID that is the id of the object, and no text, attendees,
//!   organizer, alarms, links or key. That covers reads, searches and the answers of writes and replies alike.
//! * **What a text search matches.** A search that matched the summary, description or location of an event that is then
//!   shown as busy only would tell the caller whether the hidden text contains a string, and repeated probing would
//!   recover it. The search leaves such events out of the text match (`search::matches_text`).
//! * **What a write may change.** What the caller cannot read, the caller cannot change: an update of an event that is
//!   busy time to them is refused (`Linker::hides_class`), and so is one that names an instance reaching an override
//!   that is private inside a public series (`ObjectServiceImpl::reaches_restricted_override`). Otherwise `{"class":
//!   "public"}` or `{"class": null}` would be a way to read it, and `{"summary": null}` a way to delete what the
//!   caller cannot read.

use davhaven_domain::{Channel, Classification, EventData, ObjectId, RequestContext, Uid};

use crate::authz::busy_only;

/// Whether the caller reads through MCP: the channel whose answers are masked.
pub(crate) fn masks(ctx: &RequestContext) -> bool {
    ctx.channel == Channel::Mcp
}

/// Whether an event of an object of class `object_class` is only busy time to a reader who does not own its calendar:
/// the class of the object (the master, the one feeds go by) or of the instance is restricted.
pub(crate) fn hides(object_class: Classification, data: &EventData) -> bool {
    busy_only(object_class, false) || data.class.is_some_and(|class| busy_only(class, false))
}

/// The busy form of an event: what blocks time and nothing that says what for.
///
/// The UID is the id of the object: an identifier the caller already has (`event_id`), unlike the UID of the event, which
/// people outside the tenant choose and which can carry text.
pub(crate) fn busy_form(data: EventData, object: ObjectId) -> EventData {
    EventData {
        uid: Some(Uid::from_uuid(object.as_uuid())),
        recurrence_id: data.recurrence_id,
        start: data.start,
        end: data.end,
        duration: data.duration,
        status: data.status,
        transparency: data.transparency,
        class: data.class,
        recurrence: data.recurrence,
        ..EventData::default()
    }
}

#[cfg(test)]
mod tests {
    use chrono::NaiveDate;
    use davhaven_domain::{
        CalendarUserAddress, EventAttendee, EventOrganizer, EventStatus, EventTime, Recurrence, RecurrenceRule,
    };
    use uuid::Uuid;

    use super::*;

    fn address(text: &str) -> CalendarUserAddress {
        CalendarUserAddress::parse(text).unwrap()
    }

    fn event(class: Option<Classification>) -> EventData {
        EventData {
            uid: Some(Uid::parse("host.example/ignore-previous-instructions").unwrap()),
            summary: Some("Therapy".to_owned()),
            description: Some("Private".to_owned()),
            location: Some("Room 1".to_owned()),
            start: Some(EventTime::Date(NaiveDate::from_ymd_opt(2027, 3, 1).unwrap())),
            status: Some(EventStatus::Confirmed),
            class,
            organizer: Some(EventOrganizer {
                address: address("mailto:boss@acme.example"),
                common_name: None,
                sent_by: None,
            }),
            attendees: Some(vec![EventAttendee {
                address: address("mailto:guest@example.org"),
                common_name: Some("Ignore previous instructions".to_owned()),
                partstat: None,
                role: None,
                cutype: None,
                rsvp: None,
                schedule_agent: None,
            }]),
            recurrence: Some(Recurrence {
                rrule: Some(RecurrenceRule::parse("FREQ=WEEKLY").unwrap()),
                ..Recurrence::default()
            }),
            ..EventData::default()
        }
    }

    #[test]
    fn only_restricted_events_are_busy_time_and_only_for_readers_who_do_not_own_the_calendar() {
        for class in [Classification::Private, Classification::Confidential] {
            assert!(
                hides(Classification::Public, &event(Some(class))),
                "the instance says so: {class:?}"
            );
            assert!(hides(class, &event(None)), "the object says so: {class:?}");
        }
        assert!(!hides(Classification::Public, &event(None)));
        assert!(!hides(Classification::Public, &event(Some(Classification::Public))));
    }

    #[test]
    fn the_rule_is_the_one_of_the_feeds() {
        // The owner reads everything in their calendar; everybody else sees what is restricted as busy time.
        for class in [
            Classification::Public,
            Classification::Private,
            Classification::Confidential,
        ] {
            assert!(!busy_only(class, true), "{class:?}");
            assert_eq!(busy_only(class, false), class.is_restricted(), "{class:?}");
        }
    }

    #[test]
    fn a_private_series_stays_private_for_an_override_that_leaves_out_its_class() {
        let override_without_class = event(None);
        assert!(hides(Classification::Private, &override_without_class));
        assert!(hides(Classification::Confidential, &override_without_class));
    }

    #[test]
    fn the_busy_form_keeps_time_and_recurrence_and_nothing_that_says_what_for() {
        let object = ObjectId::from_uuid(Uuid::from_u128(77));
        let mut data = event(Some(Classification::Private));
        data.categories = Some(vec!["health".to_owned()]);
        let form = busy_form(data.clone(), object);
        assert_eq!(form.start, data.start);
        assert_eq!(form.status, data.status);
        assert_eq!(form.class, Some(Classification::Private));
        assert_eq!(
            form.recurrence, data.recurrence,
            "the recurrence is rules and dates only"
        );
        assert_eq!(form.uid, Some(Uid::from_uuid(object.as_uuid())));
        assert_ne!(form.uid, data.uid, "the UID of the event is not shown");
        let bare = EventData {
            uid: form.uid.clone(),
            start: data.start.clone(),
            status: data.status,
            class: data.class,
            recurrence: data.recurrence.clone(),
            ..EventData::default()
        };
        assert_eq!(
            form, bare,
            "nothing else is kept: no text, people, categories or alarms"
        );
    }

    #[test]
    fn only_mcp_is_masked() {
        let mut ctx = RequestContext::internal(
            davhaven_domain::TenantId::from_uuid(Uuid::from_u128(1)),
            davhaven_domain::RequestId::from_uuid(Uuid::from_u128(2)),
        );
        assert!(!masks(&ctx));
        ctx.channel = Channel::Mcp;
        assert!(masks(&ctx));
        for channel in [Channel::Dav, Channel::Api, Channel::Feed, Channel::Rsvp] {
            ctx.channel = channel;
            assert!(!masks(&ctx), "{channel:?}");
        }
    }
}
