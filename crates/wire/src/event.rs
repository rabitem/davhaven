//! `EventView`: the JSON representation of calendar events.
//!
//! An event is exchanged as the fields of `EventData` (the canonical event model that `davhaven-ical` merges into
//! stored components) plus read-only metadata: ids, ETags, the DAV link and timestamps. The same type is used for
//! reading and for writing, so a client can fetch an event, change fields and send it back; the metadata is
//! ignored on write. A write is a JSON Merge Patch (RFC 7396, PLAN 2.10) for the members of the event: fields that
//! are absent keep their stored value and fields that are `null` are removed from it. A member that is an object or a
//! list replaces the stored one as a whole (`recurrence`, `organizer`, `alarms`; attendees are matched by address).
//!
//! The JSON is flat: `{"id": "...", "etag": "...", "summary": "Standup", "start": {...}, ...}`.

use chrono::{DateTime, Utc};
use davhaven_domain::{CalendarId, ETag, EventData, ExternalKey, ObjectId, ObjectUri, ScheduleTag};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;
use utoipa::openapi::RefOr;
use utoipa::openapi::schema::Schema;
use utoipa::{PartialSchema, ToSchema};

/// An event as the management API and MCP show it.
///
/// The metadata members are set by the server on read and ignored on write. The event fields of a write are merged
/// into the stored event like a JSON Merge Patch (RFC 7396) for the members of the event: a field with a value
/// replaces the stored one, an absent field keeps it and a field that is `null` removes it. A member that is an object
/// or a list replaces the stored one as a whole (`recurrence`, `organizer`, `alarms`: a `recurrence` with only
/// `exdates` drops the stored rule); attendees are matched by address and keep the parameters the write does not state.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct EventView {
    /// The id of the stored object. Read-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    /// The calendar the event is stored in. Read-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calendar_id: Option<CalendarId>,
    /// The resource name of the object inside the calendar. Read-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<ObjectUri>,
    /// The caller-chosen stable key, when the object was written with one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_key: Option<ExternalKey>,
    /// The strong entity tag of the stored bytes; identical to the DAV `getetag`. Read-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<ETag>,
    /// The `Schedule-Tag` of scheduling objects. Read-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule_tag: Option<ScheduleTag>,
    /// The absolute DAV URL of the object. Read-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dav_url: Option<Url>,
    /// When the object was created. Read-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    /// When the object was last changed. Read-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    /// The event fields.
    #[serde(flatten)]
    pub data: EventData,
}

impl EventView {
    /// A view without metadata around event fields, as a client sends it.
    pub fn from_data(data: EventData) -> Self {
        Self {
            data,
            ..Self::default()
        }
    }
}

impl From<EventData> for EventView {
    fn from(data: EventData) -> Self {
        Self::from_data(data)
    }
}

impl PartialSchema for EventView {
    fn schema() -> RefOr<Schema> {
        crate::schema::bridge::<Self>()
    }
}

impl ToSchema for EventView {
    fn schemas(schemas: &mut Vec<(String, RefOr<Schema>)>) {
        schemas.extend(crate::schema::bridged_components::<Self>());
    }
}

#[cfg(test)]
mod tests {
    use davhaven_domain::{EventField, EventTime, Uid};

    use super::*;

    fn data() -> EventData {
        EventData {
            uid: Some(Uid::parse("uid-1").unwrap()),
            summary: Some("Standup".to_owned()),
            start: Some(
                serde_json::from_value::<EventTime>(
                    serde_json::json!({"date_time": "2027-03-01T10:00:00", "time_zone": "Europe/Berlin"}),
                )
                .unwrap(),
            ),
            ..EventData::default()
        }
    }

    #[test]
    fn the_json_is_flat_and_omits_absent_metadata() {
        let view = EventView::from_data(data());
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["summary"], "Standup");
        assert_eq!(json["uid"], "uid-1");
        assert_eq!(json["start"]["time_zone"], "Europe/Berlin");
        assert!(json.get("id").is_none());
        assert!(json.get("data").is_none(), "event fields are flattened: {json}");
    }

    #[test]
    fn views_round_trip_with_metadata() {
        let mut view = EventView::from(data());
        view.id = Some(ObjectId::parse("018f3c1e-7b2a-7c3d-9e4f-0123456789ab").unwrap());
        view.etag = Some(ETag::from_bytes(b"BEGIN:VCALENDAR"));
        view.dav_url = Some(Url::parse("https://cal.example.org/dav/calendars/acme/anna/work/x.ics").unwrap());
        let json = serde_json::to_string(&view).unwrap();
        assert_eq!(serde_json::from_str::<EventView>(&json).unwrap(), view);
        let write: EventView = serde_json::from_str(r#"{"summary": "Only a title"}"#).unwrap();
        assert_eq!(write.data.summary.as_deref(), Some("Only a title"));
        assert_eq!(write.id, None);
    }

    #[test]
    fn null_members_are_removals_that_a_view_writes_back_as_null() {
        let write: EventView =
            serde_json::from_str(r#"{"id":null,"etag":null,"summary":"Only a title","location":null,"url":null}"#)
                .unwrap();
        assert_eq!(write.id, None, "metadata that is null is simply absent");
        assert_eq!(write.data.summary.as_deref(), Some("Only a title"));
        assert_eq!(
            write.data.removed,
            std::collections::BTreeSet::from([EventField::Location, EventField::Url])
        );
        assert_eq!(
            serde_json::to_value(&write).unwrap(),
            serde_json::json!({"summary": "Only a title", "location": null, "url": null}),
            "a client that sends it back says the same"
        );
        let read = EventView::from_data(data());
        let json = serde_json::to_value(&read).unwrap();
        assert!(
            json.get("location").is_none(),
            "a view that is read has nothing to remove: {json}"
        );
        let error = serde_json::from_str::<EventView>(r#"{"start":null}"#).unwrap_err();
        assert!(error.to_string().contains("`start` cannot be null"), "{error}");
    }

    #[test]
    fn the_openapi_schema_describes_metadata_and_event_fields() {
        let schema = serde_json::to_value(EventView::schema()).unwrap();
        let properties = schema["properties"].as_object().unwrap_or_else(|| panic!("{schema}"));
        for field in ["id", "etag", "dav_url", "summary", "start", "attendees"] {
            assert!(properties.contains_key(field), "{field} missing in {schema}");
        }
    }
}
