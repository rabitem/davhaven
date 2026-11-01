//! The pure domain model of Davhaven.
//!
//! This crate holds the vocabulary every other crate speaks: typed identifiers and natural keys, the entities of
//! the data model, the request context with its actor and scopes, the single authorization decision point
//! ([`authz`]), error kinds and CalDAV preconditions, resource paths and sync tokens, tenant settings, the mail
//! model, the domain and audit event catalogs and the configurable limits.
//!
//! It performs no I/O and has no async runtime, so everything in it is deterministic and cheap to test. Time and
//! randomness never appear here: identifiers, UIDs and tags are built from values the `Clock` and `IdGenerator`
//! ports supply.
//!
//! Every public item is also available at the crate root, so `davhaven_domain::TenantId` and
//! `davhaven_domain::ids::TenantId` name the same type.

#![forbid(unsafe_code)]

#[macro_use]
mod macros;

pub mod audit;
pub mod authz;
pub mod context;
pub mod credential_format;
pub mod entities;
pub mod error;
pub mod event_data;
pub mod events;
pub mod ids;
pub mod index;
pub mod keys;
pub mod limits;
pub mod mail;
pub mod path;
pub mod scope;
pub mod search;
pub mod settings;
pub mod sync;
pub mod urls;
pub mod vocab;

pub use audit::{AuditActor, AuditActorKind, AuditEvent, AuditRecord};
pub use authz::{
    Access, AccessFacts, AdminDecision, AdminOperation, BindingFact, Decision, GrantFact, Operation, Privilege,
    PrivilegeSet, Requirement, ResourceKind, ScopeRule, Subject, binding_required, can_write_events, decide,
    decide_admin, effective_access, privileges,
};
pub use context::{Actor, Channel, CredentialKind, CredentialRef, RequestContext};
pub use credential_format::{AppPasswordText, TokenText};
pub use entities::{
    ApiToken, AppPassword, Binding, Calendar, CalendarKind, ExternalAccount, ExternalAccountStatus, FeedMode,
    FeedToken, Grant, GrantAccess, GrantSource, GrantStatus, InboxItem, Notification, NotificationKind, Principal,
    PrincipalKind, PrincipalStatus, RsvpToken, StoredObject, Tenant, TenantStatus, WebhookSubscription,
};
pub use error::{ErrorKind, Precondition};
pub use event_data::{
    AlarmAction, AlarmRelated, AlarmTrigger, EventAlarm, EventAttendee, EventData, EventDataError, EventDuration,
    EventField, EventOrganizer, EventTime, EventTimeError, EventTimeRepr, Recurrence, RecurrenceRule,
    null_refused_member,
};
pub use events::{Envelope, EventPayload, EventType};
pub use ids::*;
pub use index::{AttendeeRef, ObjectIndex};
pub use keys::*;
pub use limits::{ApiLimits, DavLimits, IcalLimits, Limits, LimitsError};
pub use mail::{
    CalendarPart, ExtraHeader, HeaderName, HeaderText, MailAttachment, MailError, Mailbox, MediaType, MessageId,
    OutgoingMail,
};
pub use path::{Href, PathError, ResourcePath};
pub use scope::{Scope, ScopeSet, TokenKind, UnknownScope};
pub use search::{SearchCriterion, SearchField, TextMatch};
pub use settings::{
    ClientConfigSettings, ExternalPolicy, SchedulingSettings, SenderSettings, SettingsError, SharingSettings,
    TenantSettings,
};
pub use sync::{CollectionKey, CollectionKind, SyncToken, SyncTokenError};
pub use urls::{PublicUrls, UrlError};
pub use vocab::*;

#[cfg(test)]
mod schema_tests {
    use schemars::schema_for;

    fn schema_of<T: schemars::JsonSchema>() -> serde_json::Value {
        serde_json::to_value(schema_for!(T)).expect("schemas serialize")
    }

    #[test]
    fn contract_types_have_json_schemas() {
        let schemas = [
            schema_of::<crate::Envelope>(),
            schema_of::<crate::EventPayload>(),
            schema_of::<crate::AuditEvent>(),
            schema_of::<crate::AuditActor>(),
            schema_of::<crate::EventData>(),
            schema_of::<crate::TenantSettings>(),
            schema_of::<crate::IcalLimits>(),
            schema_of::<crate::DavLimits>(),
            schema_of::<crate::ApiLimits>(),
            schema_of::<crate::ObjectIndex>(),
            schema_of::<crate::OutgoingMail>(),
            schema_of::<crate::CredentialRef>(),
        ];
        for schema in schemas {
            assert!(schema.is_object(), "{schema}");
        }
    }

    #[test]
    fn newtypes_are_documented_as_their_wire_form() {
        assert_eq!(schema_of::<crate::TenantId>()["format"], "uuid");
        assert_eq!(schema_of::<crate::TenantSlug>()["type"], "string");
        assert_eq!(schema_of::<crate::ETag>()["type"], "string");
        assert_eq!(schema_of::<crate::TimeZoneName>()["type"], "string");
        assert_eq!(schema_of::<crate::SyncToken>()["type"], "string");
        assert_eq!(schema_of::<crate::ScopeSet>()["type"], "array");
        assert_eq!(schema_of::<crate::PrivilegeSet>()["type"], "array");
    }

    #[test]
    fn event_times_use_the_documented_representation() {
        let schema = schema_of::<crate::EventTime>();
        assert_eq!(schema["title"], "EventTime");
        let properties = schema["properties"].as_object().expect("an object schema");
        let mut names: Vec<&str> = properties.keys().map(String::as_str).collect();
        names.sort_unstable();
        assert_eq!(names, vec!["date", "date_time", "time_zone"]);
    }
}
