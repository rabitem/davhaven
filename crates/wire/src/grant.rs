//! Calendar grant views.
//!
//! A grant gives a user, a group or a service principal access to a calendar. API grants are effective immediately (`accepted`);
//! grants created by CalendarServer sharing from a client start as `pending` until the sharee answers.

use chrono::{DateTime, Utc};
use davhaven_domain::{
    CalendarId, CalendarSlug, GrantAccess, GrantId, GrantSource, GrantStatus, PrincipalId, PrincipalName,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// A grant as the management API shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct GrantView {
    /// The grant id.
    #[schema(value_type = Uuid)]
    pub id: GrantId,
    /// The shared calendar.
    #[schema(value_type = Uuid)]
    pub calendar_id: CalendarId,
    /// The slug of the shared calendar.
    #[schema(value_type = String)]
    pub calendar: CalendarSlug,
    /// The id of the user, group or service principal that is granted access.
    #[schema(value_type = Uuid)]
    pub grantee_id: PrincipalId,
    /// The name of the user, group or service principal that is granted access.
    #[schema(value_type = String)]
    pub grantee: PrincipalName,
    /// The access level.
    #[schema(schema_with = crate::schema::grant_access)]
    pub access: GrantAccess,
    /// Pending, accepted or declined.
    #[schema(schema_with = crate::schema::grant_status)]
    pub status: GrantStatus,
    /// Whether the API or a client created the grant.
    #[schema(schema_with = crate::schema::grant_source)]
    pub source: GrantSource,
    /// Whether the calendar is **required** for the people the grant reaches (see [`GrantWrite::required`]). Always
    /// `false` for a grant a client created.
    pub required: bool,
    /// When the grant was created.
    pub created_at: DateTime<Utc>,
    /// When the grant was last changed.
    pub updated_at: DateTime<Utc>,
    /// The optimistic concurrency counter; the `ETag` is derived from it.
    pub version: i64,
}

/// The body of a grant `PUT`: create or replace the grant of the grantee named in the path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantWrite {
    /// The access level.
    #[schema(schema_with = crate::schema::grant_access)]
    pub access: GrantAccess,
    /// Whether the calendar is **required** for the people the grant reaches: the grantee, or the members of a grantee
    /// group. They cannot remove it from their calendar home, so a `DELETE` of its collection from a client is refused
    /// (403, `DAV:need-privileges` naming `DAV:unbind`) instead of hiding the calendar for good; a binding that was
    /// hidden before (also one hidden before its owner joined the group) is shown again. Without the flag (the default) the
    /// calendar is optional: a client that deletes the collection hides it, and the binding can be restored through
    /// `POST …/bindings/{binding}/restore`. The flag belongs to the grant, so a `PUT` that leaves it out sets it to `false`
    /// (send it on every `PUT`); it has no effect while the grant is not accepted (API grants always are). Only a tenant
    /// token sets or clears it: a principal's token is refused with 403 when it asks for `true`, and a grant it puts keeps
    /// the flag it has.
    #[serde(default)]
    pub required: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_writes_carry_the_access_level_and_the_required_flag() {
        let write: GrantWrite = serde_json::from_str(r#"{"access": "read_write"}"#).unwrap();
        assert_eq!(write.access, GrantAccess::ReadWrite);
        assert!(
            !write.required,
            "a calendar is optional unless the grant says otherwise"
        );
        let required: GrantWrite = serde_json::from_str(r#"{"access": "read", "required": true}"#).unwrap();
        assert!(required.required);
        assert!(serde_json::from_str::<GrantWrite>(r#"{"access": "owner"}"#).is_err());
        assert!(serde_json::from_str::<GrantWrite>(r#"{"access": "read", "status": "pending"}"#).is_err());
        assert!(serde_json::from_str::<GrantWrite>(r#"{"access": "read", "required": "yes"}"#).is_err());
    }
}
