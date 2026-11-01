//! Principal views and membership sets.
//!
//! A principal is a user, a group, a resource or a service. The management API addresses principals by their
//! immutable `name` (the login local-part); every view also carries the id and the DAV URL of the principal
//! resource.

use chrono::{DateTime, Utc};
use davhaven_domain::{
    CalendarUserAddress, Email, Locale, PrincipalId, PrincipalKind, PrincipalName, PrincipalStatus, TimeZoneName,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;
use utoipa::ToSchema;

/// A principal as the management API shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct PrincipalView {
    /// The principal id.
    #[schema(value_type = Uuid)]
    pub id: PrincipalId,
    /// What the principal represents.
    #[schema(schema_with = crate::schema::principal_kind)]
    pub kind: PrincipalKind,
    /// The immutable login local-part.
    #[schema(value_type = String)]
    pub name: PrincipalName,
    /// The display name.
    pub display_name: String,
    /// The primary e-mail address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub email: Option<Email>,
    /// Further calendar user addresses (`mailto:` addresses or URLs) besides the primary one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<String>)]
    pub addresses: Vec<CalendarUserAddress>,
    /// The preferred locale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub locale: Option<Locale>,
    /// The preferred time zone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub timezone: Option<TimeZoneName>,
    /// The identifier of the principal in the system that provisions it, unique per tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<String>,
    /// The lifecycle status.
    #[schema(schema_with = crate::schema::principal_status)]
    pub status: PrincipalStatus,
    /// The absolute URL of the principal resource in the DAV namespace.
    #[schema(value_type = String)]
    pub dav_url: Url,
    /// When the principal was created.
    pub created_at: DateTime<Utc>,
    /// When the principal was last changed.
    pub updated_at: DateTime<Utc>,
    /// The optimistic concurrency counter; the `ETag` is derived from it.
    pub version: i64,
}

/// The body of a principal `PUT`: create or replace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PrincipalWrite {
    /// What the principal represents. The kind of an existing principal cannot change.
    #[schema(schema_with = crate::schema::principal_kind)]
    pub kind: PrincipalKind,
    /// The display name.
    pub display_name: String,
    /// The primary e-mail address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub email: Option<Email>,
    /// Further calendar user addresses; replaces the stored list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<String>)]
    pub addresses: Vec<CalendarUserAddress>,
    /// The preferred locale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub locale: Option<Locale>,
    /// The preferred time zone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub timezone: Option<TimeZoneName>,
    /// The identifier of the principal in the provisioning system, unique per tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<String>,
    /// The status; defaults to `active`. `deleted` is reached through `DELETE` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(schema_with = crate::schema::principal_status)]
    pub status: Option<PrincipalStatus>,
}

/// The full member set of a group, as used by `PUT` and `GET` on `…/members`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MembershipSet {
    /// The names of the member principals (users, resources or services of the same tenant), sorted.
    #[schema(value_type = Vec<String>)]
    pub members: Vec<PrincipalName>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_accept_a_minimal_body_and_reject_unknown_members() {
        let write: PrincipalWrite =
            serde_json::from_str(r#"{"kind": "user", "display_name": "Anna", "email": "Anna@Example.org"}"#).unwrap();
        assert_eq!(write.kind, PrincipalKind::User);
        assert_eq!(write.email.unwrap().as_str(), "anna@example.org");
        assert_eq!(write.addresses.len(), 0);
        assert!(
            serde_json::from_str::<PrincipalWrite>(r#"{"kind": "user", "display_name": "A", "nick": "a"}"#).is_err()
        );
        assert!(serde_json::from_str::<PrincipalWrite>(r#"{"display_name": "A"}"#).is_err());
    }

    #[test]
    fn membership_sets_are_plain_name_lists() {
        let set: MembershipSet = serde_json::from_str(r#"{"members": ["anna", "ben"]}"#).unwrap();
        assert_eq!(set.members.len(), 2);
        assert_eq!(serde_json::to_string(&set).unwrap(), r#"{"members":["anna","ben"]}"#);
        assert!(serde_json::from_str::<MembershipSet>(r#"{"members": ["Not Valid"]}"#).is_err());
    }
}
