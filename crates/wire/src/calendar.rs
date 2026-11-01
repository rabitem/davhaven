//! Calendar views.
//!
//! `CalendarView` is what the management API returns for a calendar, `CalendarWrite` the body of
//! `PUT /tenants/{tenant}/principals/{principal}/calendars/{calendar}`. Path segments are the immutable natural
//! keys (the owner's principal name and the calendar slug); every view also carries the ids and the DAV URL.

use chrono::{DateTime, Utc};
use davhaven_domain::{
    BindingId, CalendarId, CalendarKind, CalendarSlug, ComponentKind, PrincipalId, PrincipalName, SyncToken,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;
use utoipa::ToSchema;

/// A calendar as the management API shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct CalendarView {
    /// The calendar id.
    #[schema(value_type = Uuid)]
    pub id: CalendarId,
    /// The id of the owning principal (a user, a group, a resource or a service).
    #[schema(value_type = Uuid)]
    pub owner_id: PrincipalId,
    /// The name of the owning principal.
    #[schema(value_type = String)]
    pub owner: PrincipalName,
    /// The immutable slug, unique per owner among live calendars.
    #[schema(value_type = String)]
    pub slug: CalendarSlug,
    /// The kind of calendar.
    #[schema(schema_with = crate::schema::calendar_kind)]
    pub kind: CalendarKind,
    /// The display name.
    pub display_name: String,
    /// The description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The color as `#RRGGBB` or `#RRGGBBAA`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    /// The sort order hint for clients.
    pub sort_order: i32,
    /// The component types the calendar accepts.
    #[schema(value_type = Vec<String>)]
    pub components: Vec<ComponentKind>,
    /// The current sync token; it is also the `getctag` of the collection.
    #[schema(value_type = String)]
    pub sync_token: SyncToken,
    /// The absolute DAV URL of the calendar collection in the owner's home.
    #[schema(value_type = String)]
    pub dav_url: Url,
    /// When the calendar was created.
    pub created_at: DateTime<Utc>,
    /// When the calendar was last changed.
    pub updated_at: DateTime<Utc>,
    /// The optimistic concurrency counter; the `ETag` is derived from it.
    pub version: i64,
}

/// A calendar in the home of a principal, as the management API lists it: the **binding** through which the principal's
/// calendar apps see the calendar, whether or not the principal removed it from the home.
///
/// A principal who deletes a shared calendar (a group calendar, a managed one, a calendar of someone else) in a calendar
/// app hides the binding; the calendar is not deleted and the grant stays. `hidden` says so, and
/// `POST …/bindings/{binding}/restore` shows the calendar again. `required` says that the principal cannot remove the
/// calendar at all (a grant with the `required` flag reaches them).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct HomeBindingView {
    /// The binding id.
    #[schema(value_type = Uuid)]
    pub id: BindingId,
    /// The name of the principal whose home lists the binding.
    #[schema(value_type = String)]
    pub principal: PrincipalName,
    /// The slug of the collection in the principal's home: the last segment of the DAV path and the `{binding}` of the
    /// restore path. It can differ from the calendar's own slug.
    #[schema(value_type = String)]
    pub slug: CalendarSlug,
    /// The calendar behind the binding.
    #[schema(value_type = Uuid)]
    pub calendar_id: CalendarId,
    /// The name of the owner of the calendar.
    #[schema(value_type = String)]
    pub owner: PrincipalName,
    /// The slug of the calendar under its owner: the key of the calendar's own resources in the API.
    #[schema(value_type = String)]
    pub calendar: CalendarSlug,
    /// The kind of calendar.
    #[schema(schema_with = crate::schema::calendar_kind)]
    pub kind: CalendarKind,
    /// The name the principal sees: their own name for the calendar, or the calendar's.
    pub display_name: String,
    /// Whether the principal removed the calendar from their home: calendar apps no longer list it.
    pub hidden: bool,
    /// Whether the calendar is required for the principal: an accepted grant with the `required` flag reaches them, so a
    /// calendar app cannot remove it.
    pub required: bool,
    /// The absolute DAV URL of the collection in the principal's home.
    #[schema(value_type = String)]
    pub dav_url: Url,
    /// When the binding was created.
    pub created_at: DateTime<Utc>,
    /// When the binding was last changed.
    pub updated_at: DateTime<Utc>,
    /// The version counter of the binding; it grows with every change of the binding. A binding has no `ETag` of its own.
    pub version: i64,
}

/// The body of a calendar `PUT`: create or replace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarWrite {
    /// The kind of calendar to create (`user`, `managed`, `group`); defaults to `user`. The kind of an existing
    /// calendar cannot change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(schema_with = crate::schema::calendar_kind)]
    pub kind: Option<CalendarKind>,
    /// The display name.
    pub display_name: String,
    /// The description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The color as `#RRGGBB` or `#RRGGBBAA`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    /// The sort order hint; defaults to 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort_order: Option<i32>,
    /// The component types the calendar accepts; defaults to the tenant's allowed components.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Vec<String>>)]
    pub components: Option<Vec<ComponentKind>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_reject_unknown_fields_and_need_a_display_name() {
        let write: CalendarWrite = serde_json::from_str(r#"{"display_name": "Team", "kind": "managed"}"#).unwrap();
        assert_eq!(write.kind, Some(CalendarKind::Managed));
        assert!(serde_json::from_str::<CalendarWrite>(r#"{"display_name": "Team", "colour": "blue"}"#).is_err());
        assert!(serde_json::from_str::<CalendarWrite>(r"{}").is_err());
    }

    #[test]
    fn views_serialize_with_documented_member_names() {
        let view = CalendarView {
            id: CalendarId::parse("018f3c1e-7b2a-7c3d-9e4f-000000000001").unwrap(),
            owner_id: PrincipalId::parse("018f3c1e-7b2a-7c3d-9e4f-000000000002").unwrap(),
            owner: PrincipalName::parse("anna").unwrap(),
            slug: CalendarSlug::parse("work").unwrap(),
            kind: CalendarKind::User,
            display_name: "Work".to_owned(),
            description: None,
            color: Some("#336699".to_owned()),
            sort_order: 3,
            components: vec![ComponentKind::Event],
            sync_token: SyncToken::new(uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2), 7),
            dav_url: Url::parse("https://cal.example.org/dav/calendars/acme/anna/work/").unwrap(),
            created_at: DateTime::UNIX_EPOCH,
            updated_at: DateTime::UNIX_EPOCH,
            version: 4,
        };
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["owner"], "anna");
        assert_eq!(json["slug"], "work");
        assert_eq!(json["kind"], "user");
        assert_eq!(json["components"], serde_json::json!(["event"]));
        assert!(json.get("description").is_none());
        assert!(json["sync_token"].as_str().unwrap().starts_with("urn:davhaven:sync:"));
        assert_eq!(serde_json::from_value::<CalendarView>(json).unwrap(), view);
    }
}
