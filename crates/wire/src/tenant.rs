//! Tenant views.
//!
//! Tenants are managed with system tokens (`system:tenants`) and addressed by their immutable slug.

use chrono::{DateTime, Utc};
use davhaven_domain::{DomainName, TenantId, TenantSettings, TenantSlug, TenantStatus};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// A tenant as the management API shows it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct TenantView {
    /// The tenant id.
    #[schema(value_type = Uuid)]
    pub id: TenantId,
    /// The immutable slug used in DAV and API paths.
    #[schema(value_type = String)]
    pub slug: TenantSlug,
    /// The display name.
    pub display_name: String,
    /// The domain of `name@login_domain` logins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub login_domain: Option<DomainName>,
    /// The lifecycle status.
    #[schema(schema_with = crate::schema::tenant_status)]
    pub status: TenantStatus,
    /// The tenant settings.
    #[schema(schema_with = crate::schema::tenant_settings)]
    pub settings: TenantSettings,
    /// When the tenant was created.
    pub created_at: DateTime<Utc>,
    /// When the tenant was last changed.
    pub updated_at: DateTime<Utc>,
    /// The optimistic concurrency counter; the `ETag` is derived from it.
    pub version: i64,
}

/// The body of a tenant `PUT`: create or replace.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TenantWrite {
    /// The display name.
    pub display_name: String,
    /// The domain of `name@login_domain` logins, unique across tenants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub login_domain: Option<DomainName>,
    /// The status; defaults to `active`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(schema_with = crate::schema::tenant_status)]
    pub status: Option<TenantStatus>,
    /// The settings; absent settings keep their defaults on create and their stored values on replace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(schema_with = crate::schema::tenant_settings)]
    pub settings: Option<TenantSettings>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_need_only_a_display_name() {
        let write: TenantWrite = serde_json::from_str(r#"{"display_name": "Acme"}"#).unwrap();
        assert_eq!(write.display_name, "Acme");
        assert!(write.settings.is_none() && write.login_domain.is_none() && write.status.is_none());
        let with_settings: TenantWrite =
            serde_json::from_str(r#"{"display_name": "Acme", "settings": {"feeds_enabled": false}}"#).unwrap();
        assert!(!with_settings.settings.unwrap().feeds_enabled);
    }

    #[test]
    fn views_carry_the_typed_settings() {
        let view = TenantView {
            id: TenantId::parse("018f3c1e-7b2a-7c3d-9e4f-000000000001").unwrap(),
            slug: TenantSlug::parse("acme").unwrap(),
            display_name: "Acme".to_owned(),
            login_domain: Some(DomainName::parse("acme.example").unwrap()),
            status: TenantStatus::Active,
            settings: TenantSettings::default(),
            created_at: DateTime::UNIX_EPOCH,
            updated_at: DateTime::UNIX_EPOCH,
            version: 1,
        };
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["slug"], "acme");
        assert_eq!(
            json["settings"]["theme"],
            serde_json::Value::Null,
            "a tenant without a theme of its own names none (the deployment decides), and the member is there like the other optional settings"
        );
        assert_eq!(serde_json::from_value::<TenantView>(json).unwrap(), view);
    }
}
