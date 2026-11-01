//! Export of JSON schemas for contracts and drift checks.
//!
//! The wire types derive `schemars::JsonSchema` (the source of the MCP tool schemas and the event schemas) and
//! `utoipa::ToSchema` (the source of the OpenAPI document). This module holds what both worlds share:
//!
//! * [`json_schema`] renders the JSON Schema of any wire or domain type;
//! * [`events_schema`] is the committed `events.schema.json`: the envelope and the payload of every event type;
//! * the bridge from `schemars` to OpenAPI for the types of the domain crate, which cannot derive `ToSchema`
//!   themselves (the crate has no OpenAPI dependency): [`try_bridge`] converts the `schemars` schema of a type into
//!   an OpenAPI schema and the components it refers to, and [`shared_components`] lists the domain types that
//!   several wire types use, so that an OpenAPI document registers each of them once.
//!
//! # The bridge
//!
//! `schemars` and OpenAPI 3.1 both speak JSON Schema 2020-12, but the `utoipa` types that carry an OpenAPI document
//! do not read all of it. The conversion therefore rewrites what they would drop:
//!
//! * `const` becomes a one-value `enum` (an internally tagged union keeps the tag of every alternative);
//! * alternatives that are only string constants, which is how `schemars` writes an enumeration whose variants
//!   have documentation, become one string `enum`, and the documentation of the variants moves into the description.
//!   Without this step the values of the enumeration are lost and clients cannot tell what to send;
//! * every type that has a name stays a component (`#/components/schemas/{Name}`) instead of being copied into
//!   each schema that uses it, except the named primitives (an id, a time zone name, a locale: a string with a
//!   format and a description), which become plain `string` properties. A property that refers to such a type and
//!   has a default (`"default": "en"`) breaks generators, which treat the default of a reference as code, and a
//!   client gains nothing from a type that is only a string;
//! * `anyOf` of a primitive and `null` becomes `type: [primitive, "null"]`;
//! * an internally tagged union (`#[serde(tag = "type")]`) becomes a polymorphic type: every alternative is a
//!   component of its own (`AlarmTriggerRelative`) and the union names the tag as its `discriminator`. Generators
//!   cannot tell the alternatives of a plain `oneOf` apart and fail to read a value that two of them accept.
//!
//! `xtask contracts` writes the documents and, with `--check`, fails when the committed files are out of date.

use std::collections::BTreeMap;

use davhaven_domain::events::{
    CalendarPayload, ENVELOPE_VERSION, GrantPayload, MailFailurePayload, MembershipPayload, ObjectsChangedPayload,
    PrincipalPayload, RsvpPayload, SchedulingReplyPayload, WebhookPayload,
};
use davhaven_domain::{
    Access, CalendarKind, EventStatus, EventType, ExternalAccountStatus, FeedMode, GrantAccess, GrantSource,
    GrantStatus, PartStat, PrincipalKind, PrincipalStatus, TenantStatus, TokenKind, Transparency,
};
use schemars::JsonSchema;
use schemars::generate::SchemaSettings;
use serde::de::Error as _;
use serde_json::{Map, Value, json};
use utoipa::openapi::schema::{Object, Schema};
use utoipa::openapi::{Ref, RefOr};

use crate::webhook::WebhookEnvelope;

/// The JSON Schema (draft 2020-12) of `T`, with every referenced type under `$defs`.
pub fn json_schema<T: JsonSchema + ?Sized>() -> Value {
    let generator = SchemaSettings::draft2020_12().into_generator();
    let schema = generator.into_root_schema_for::<T>();
    serde_json::to_value(&schema).unwrap_or(Value::Null)
}

/// The place `schemars` puts definitions: a JSON pointer, so that a reference reads `#/components/schemas/{Name}`.
const COMPONENTS_POINTER: &str = "/components/schemas";

/// The type name of a JSON value, for a schema that has a `const` but no `type`.
fn json_type(value: &Value) -> Option<&'static str> {
    match value {
        Value::String(_) => Some("string"),
        Value::Bool(_) => Some("boolean"),
        Value::Number(number) if number.is_i64() || number.is_u64() => Some("integer"),
        Value::Number(_) => Some("number"),
        Value::Null => Some("null"),
        Value::Array(_) | Value::Object(_) => None,
    }
}

/// Replaces `const` by a one-value `enum`. A member named `const` of a `properties` map holds a schema (an object),
/// never a constant, so objects are left alone.
fn replace_const(members: &mut Map<String, Value>) {
    if members.get("const").is_none_or(Value::is_object) {
        return;
    }
    if let Some(constant) = members.remove("const") {
        if !members.contains_key("type")
            && let Some(kind) = json_type(&constant)
        {
            members.insert("type".to_owned(), json!(kind));
        }
        members.insert("enum".to_owned(), Value::Array(vec![constant]));
    }
}

/// The value and the documentation of an alternative that is nothing but one string constant.
fn string_constant(alternative: &Value) -> Option<(String, Option<String>)> {
    let object = alternative.as_object()?;
    if !object
        .keys()
        .all(|key| matches!(key.as_str(), "type" | "enum" | "description"))
        || object.get("type") != Some(&json!("string"))
    {
        return None;
    }
    let [Value::String(name)] = object.get("enum")?.as_array()?.as_slice() else {
        return None;
    };
    let note = object
        .get("description")
        .and_then(Value::as_str)
        .map(|text| text.split_whitespace().collect::<Vec<_>>().join(" "));
    Some((name.clone(), note))
}

/// Turns `oneOf` or `anyOf` alternatives that are all string constants into one string `enum`.
///
/// The description of the enumeration keeps its own text and gains one line per documented value.
fn collapse_string_alternatives(members: &mut Map<String, Value>, keyword: &str) {
    let Some(Value::Array(alternatives)) = members.get(keyword) else {
        return;
    };
    if alternatives.len() < 2 {
        return;
    }
    let Some(constants) = alternatives.iter().map(string_constant).collect::<Option<Vec<_>>>() else {
        return;
    };
    members.remove(keyword);
    let notes: Vec<String> = constants
        .iter()
        .filter_map(|(name, note)| note.as_ref().map(|note| format!("- `{name}`: {note}")))
        .collect();
    let values: Vec<Value> = constants.into_iter().map(|(name, _)| Value::String(name)).collect();
    members.insert("type".to_owned(), json!("string"));
    members.insert("enum".to_owned(), Value::Array(values));
    if !notes.is_empty() {
        let mut description = members
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_default();
        if !description.is_empty() {
            description.push_str("\n\n");
        }
        description.push_str("Values:\n");
        description.push_str(&notes.join("\n"));
        members.insert("description".to_owned(), Value::String(description));
    }
}

/// The prefix of references to components.
const COMPONENT_PREFIX: &str = "#/components/schemas/";

/// The keywords a named primitive may have: a type and its constraints and documentation, nothing structural.
const PRIMITIVE_KEYWORDS: [&str; 9] = [
    "type",
    "format",
    "description",
    "title",
    "minimum",
    "maximum",
    "minLength",
    "maxLength",
    "pattern",
];

/// Whether `type` names a primitive JSON type.
fn is_primitive_type(kind: Option<&Value>) -> bool {
    matches!(
        kind.and_then(Value::as_str),
        Some("string" | "integer" | "number" | "boolean")
    )
}

/// Whether a schema is a plain primitive: a primitive type with at most a format, constraints and a description.
fn is_plain_primitive(object: &Map<String, Value>) -> bool {
    is_primitive_type(object.get("type")) && object.keys().all(|key| PRIMITIVE_KEYWORDS.contains(&key.as_str()))
}

/// Replaces every reference to a named primitive by the primitive itself. What the referencing schema says (its
/// description, its default) wins over what the type says.
fn inline_aliases(value: &mut Value, aliases: &BTreeMap<String, Map<String, Value>>) {
    match value {
        Value::Object(members) => {
            for member in members.values_mut() {
                inline_aliases(member, aliases);
            }
            let alias = members
                .get("$ref")
                .and_then(Value::as_str)
                .and_then(|target| target.strip_prefix(COMPONENT_PREFIX))
                .and_then(|name| aliases.get(name));
            if let Some(alias) = alias {
                members.remove("$ref");
                for (key, member) in alias {
                    members.entry(key.clone()).or_insert_with(|| member.clone());
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                inline_aliases(item, aliases);
            }
        }
        _ => {}
    }
}

/// Turns `anyOf: [primitive, {"type": "null"}]` into the primitive with `type: [primitive, "null"]`; what the outer
/// schema says (description, default) wins over what the primitive says.
fn merge_nullable_primitive(members: &mut Map<String, Value>) {
    let Some(Value::Array(alternatives)) = members.get("anyOf") else {
        return;
    };
    let [first, second] = alternatives.as_slice() else {
        return;
    };
    let null = json!({"type": "null"});
    let primitive = if *second == null {
        first
    } else if *first == null {
        second
    } else {
        return;
    };
    let Some(primitive) = primitive.as_object().filter(|object| is_plain_primitive(object)) else {
        return;
    };
    let primitive = primitive.clone();
    members.remove("anyOf");
    for (key, member) in primitive {
        if key == "type" {
            members.insert(key, json!([member, "null"]));
        } else {
            members.entry(key).or_insert(member);
        }
    }
}

/// Rewrites a `schemars` schema into the form the OpenAPI types read (see the module documentation).
fn normalize(value: &mut Value) {
    match value {
        Value::Object(members) => {
            for member in members.values_mut() {
                normalize(member);
            }
            replace_const(members);
            collapse_string_alternatives(members, "oneOf");
            collapse_string_alternatives(members, "anyOf");
            merge_nullable_primitive(members);
        }
        Value::Array(items) => {
            for item in items {
                normalize(item);
            }
        }
        _ => {}
    }
}

/// The tag value of an alternative of an internally tagged union: an object whose required `type` property has
/// exactly one string value.
fn tag_of(alternative: &Value) -> Option<String> {
    let object = alternative.as_object()?;
    let required = object.get("required")?.as_array()?;
    if !required.iter().any(|name| name == "type") {
        return None;
    }
    let tag = object.get("properties")?.get("type")?.get("enum")?.as_array()?;
    match tag.as_slice() {
        [Value::String(tag)] => Some(tag.clone()),
        _ => None,
    }
}

/// The tag in upper camel case: `absolute` becomes `Absolute`, `this_and_future` `ThisAndFuture`.
fn pascal_case(tag: &str) -> String {
    let mut name = String::new();
    for word in tag
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
    {
        let mut letters = word.chars();
        if let Some(first) = letters.next() {
            name.extend(first.to_uppercase());
            name.push_str(letters.as_str());
        }
    }
    name
}

/// Turns a union of tagged objects into a polymorphic type: each alternative moves into the component
/// `{parent}{Tag}`, the union refers to them and names `type` as its discriminator. Unions whose alternatives are
/// not all tagged objects are left alone. The new components are appended to `hoisted`.
fn hoist_tagged_union(parent: &str, schema: &mut Value, hoisted: &mut Vec<(String, Value)>) {
    let Some(members) = schema.as_object_mut() else {
        return;
    };
    let Some(Value::Array(alternatives)) = members.get("oneOf") else {
        return;
    };
    let Some(tags) = alternatives.iter().map(tag_of).collect::<Option<Vec<_>>>() else {
        return;
    };
    if tags.len() < 2 {
        return;
    }
    let Some(Value::Array(alternatives)) = members.remove("oneOf") else {
        return;
    };
    let mut references = Vec::with_capacity(alternatives.len());
    let mut mapping = Map::new();
    for (tag, alternative) in tags.into_iter().zip(alternatives) {
        let name = format!("{parent}{}", pascal_case(&tag));
        let target = format!("{COMPONENT_PREFIX}{name}");
        references.push(json!({"$ref": target}));
        mapping.insert(tag, Value::String(target));
        hoisted.push((name, alternative));
    }
    members.insert("oneOf".to_owned(), Value::Array(references));
    members.insert(
        "discriminator".to_owned(),
        json!({"propertyName": "type", "mapping": Value::Object(mapping)}),
    );
}

/// The OpenAPI schema of a type and the components it refers to.
#[derive(Clone)]
pub struct Bridged {
    /// The schema of the type itself. Where it refers to another type it uses `#/components/schemas/{Name}`.
    pub schema: RefOr<Schema>,
    /// The definitions of the types the schema refers to, by component name.
    pub components: Vec<(String, RefOr<Schema>)>,
}

/// Converts the `schemars` schema of `T` into an OpenAPI schema and the components it refers to.
///
/// # Errors
///
/// A [`serde_json::Error`] when the converted schema cannot be read as an OpenAPI schema. The schemas of the types
/// of this crate always can: the tests convert every one of them.
pub fn try_bridge<T: JsonSchema + ?Sized>() -> Result<Bridged, serde_json::Error> {
    let generator = SchemaSettings::draft2020_12()
        .with(|settings| settings.definitions_path = COMPONENTS_POINTER.into())
        .into_generator();
    let schema = generator.into_root_schema_for::<T>();
    let Value::Object(mut root) = serde_json::to_value(&schema)? else {
        return Err(serde_json::Error::custom("the schema of a type is a JSON object"));
    };
    root.remove("$schema");
    // The name of a type is the key of its component; the root schema repeats it as a title the definitions lack.
    root.remove("title");
    let definitions = match root.remove("components") {
        Some(Value::Object(mut components)) => match components.remove("schemas") {
            Some(Value::Object(schemas)) => schemas,
            _ => Map::new(),
        },
        _ => Map::new(),
    };
    let mut aliases = BTreeMap::new();
    let mut named = Vec::new();
    for (name, definition) in definitions {
        match definition {
            Value::Object(object) if is_plain_primitive(&object) => {
                aliases.insert(name, object);
            }
            other => named.push((name, other)),
        }
    }
    let mut root = Value::Object(root);
    inline_aliases(&mut root, &aliases);
    normalize(&mut root);
    let mut hoisted = Vec::new();
    hoist_tagged_union(&T::schema_name(), &mut root, &mut hoisted);
    let mut components = Vec::with_capacity(named.len());
    for (name, mut definition) in named {
        inline_aliases(&mut definition, &aliases);
        normalize(&mut definition);
        hoist_tagged_union(&name, &mut definition, &mut hoisted);
        components.push((name, definition));
    }
    components.extend(hoisted);
    let components = components
        .into_iter()
        .map(|(name, definition)| Ok((name, serde_json::from_value(definition)?)))
        .collect::<Result<Vec<_>, serde_json::Error>>()?;
    Ok(Bridged {
        schema: serde_json::from_value(root)?,
        components,
    })
}

/// The OpenAPI schema of `T` without its components, for `PartialSchema` implementations of types that are built
/// from `schemars` schemas. If the schema cannot be converted the result is an unconstrained object, which keeps
/// documentation generation total; the tests convert every type that uses this function.
pub fn bridge<T: JsonSchema + ?Sized>() -> RefOr<Schema> {
    try_bridge::<T>().map_or_else(
        |_| RefOr::T(Schema::Object(Object::default())),
        |bridged| bridged.schema,
    )
}

/// The components `T`'s schema refers to, for `ToSchema::schemas` of types that are built with [`bridge`].
pub fn bridged_components<T: JsonSchema + ?Sized>() -> Vec<(String, RefOr<Schema>)> {
    try_bridge::<T>().map_or_else(|_| Vec::new(), |bridged| bridged.components)
}

/// A reference to the component of `T`, for the fields of derived `ToSchema` types.
fn reference<T: JsonSchema + ?Sized>() -> RefOr<Schema> {
    RefOr::Ref(Ref::from_schema_name(T::schema_name()))
}

/// Adds the component of `T` and the components it refers to; the first definition of a name stays.
fn add_component<T: JsonSchema + ?Sized>(named: &mut BTreeMap<String, RefOr<Schema>>) {
    if let Ok(bridged) = try_bridge::<T>() {
        named.entry(T::schema_name().into_owned()).or_insert(bridged.schema);
        for (name, schema) in bridged.components {
            named.entry(name).or_insert(schema);
        }
    }
}

macro_rules! shared_schemas {
    ($($(#[$meta:meta])* $function:ident => $ty:ty),+ $(,)?) => {
        $(
            $(#[$meta])*
            pub(crate) fn $function() -> RefOr<Schema> {
                reference::<$ty>()
            }
        )+

        /// The components of the domain types that wire types refer to by name (enumerations such as
        /// `CalendarKind`, objects such as `TenantSettings`) and of the types they refer to in turn.
        ///
        /// Fields of these types are references (`#/components/schemas/{Name}`) in the schemas of the wire
        /// types. An OpenAPI document that contains such a wire type registers this list once, which gives
        /// every enumeration and every shared object exactly one definition; the API crate does so and drops
        /// what no operation reaches.
        pub fn shared_components() -> Vec<(String, RefOr<Schema>)> {
            let mut named = BTreeMap::new();
            $( add_component::<$ty>(&mut named); )+
            named.into_iter().collect()
        }
    };
}

shared_schemas! {
    /// Reference to `CalendarKind`.
    calendar_kind => CalendarKind,
    /// Reference to `PrincipalKind`.
    principal_kind => PrincipalKind,
    /// Reference to `PrincipalStatus`.
    principal_status => PrincipalStatus,
    /// Reference to `TenantStatus`.
    tenant_status => TenantStatus,
    /// Reference to `GrantAccess`.
    grant_access => GrantAccess,
    /// Reference to `GrantStatus`.
    grant_status => GrantStatus,
    /// Reference to `GrantSource`.
    grant_source => GrantSource,
    /// Reference to `FeedMode`.
    feed_mode => FeedMode,
    /// Reference to `TokenKind`.
    token_kind => TokenKind,
    /// Reference to `EventType`.
    event_type => EventType,
    /// Reference to `ExternalAccountStatus`.
    external_account_status => ExternalAccountStatus,
    /// Reference to `PartStat`.
    part_stat => PartStat,
    /// Reference to `Access`.
    access => Access,
    /// Reference to `Transparency`.
    transparency => Transparency,
    /// Reference to `EventStatus`.
    event_status => EventStatus,
    /// Reference to `AuditActor`.
    audit_actor => davhaven_domain::AuditActor,
    /// Reference to `TenantSettings`.
    tenant_settings => davhaven_domain::TenantSettings,
    /// Reference to `EventData`.
    event_data => davhaven_domain::EventData,
    /// Reference to `EventTime`.
    event_time => davhaven_domain::EventTime,
    /// Reference to `Recurrence`.
    recurrence => davhaven_domain::Recurrence,
}

/// The payload schema of one event type, as a JSON Schema document.
fn payload_schema(event_type: EventType) -> Value {
    match event_type {
        EventType::PrincipalCreated | EventType::PrincipalUpdated | EventType::PrincipalDeleted => {
            json_schema::<PrincipalPayload>()
        }
        EventType::MembershipChanged => json_schema::<MembershipPayload>(),
        EventType::CalendarCreated | EventType::CalendarUpdated | EventType::CalendarDeleted => {
            json_schema::<CalendarPayload>()
        }
        EventType::CalendarObjectsChanged => json_schema::<ObjectsChangedPayload>(),
        EventType::GrantCreated
        | EventType::GrantUpdated
        | EventType::GrantDeleted
        | EventType::ShareInvited
        | EventType::ShareAccepted
        | EventType::ShareDeclined => json_schema::<GrantPayload>(),
        EventType::SchedulingReplyReceived | EventType::SchedulingReplyRejected => {
            json_schema::<SchedulingReplyPayload>()
        }
        EventType::RsvpAnswered => json_schema::<RsvpPayload>(),
        EventType::MailDeliveryFailed => json_schema::<MailFailurePayload>(),
        EventType::ExternalAccountSyncFailed => json_schema::<davhaven_domain::events::ExternalAccountPayload>(),
        EventType::WebhookDisabled | EventType::WebhookPing => json_schema::<WebhookPayload>(),
    }
}

/// The content of `events.schema.json`: the webhook envelope and the payload schema of every event type, in
/// catalog order. Event types and payload shapes only grow (PLAN 2.11), so a drift in this document is a contract
/// change that needs review.
pub fn events_schema() -> Value {
    let events: Vec<Value> = EventType::ALL
        .iter()
        .map(|event_type| {
            json!({
                "type": event_type.as_str(),
                "payload": payload_schema(*event_type),
            })
        })
        .collect();
    json!({
        "title": "Davhaven domain events",
        "envelope_version": ENVELOPE_VERSION,
        "envelope": json_schema::<WebhookEnvelope>(),
        "events": events,
    })
}

#[cfg(test)]
mod tests {
    use davhaven_domain::{EventData, Scope};

    use super::*;

    #[test]
    fn json_schemas_render_for_domain_and_wire_types() {
        let schema = json_schema::<WebhookEnvelope>();
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"]["type"].is_object());
    }

    /// The component of `name` among `components`, as JSON.
    fn component(components: &[(String, RefOr<Schema>)], name: &str) -> Value {
        components.iter().find(|(candidate, _)| candidate == name).map_or_else(
            || {
                let names: Vec<&String> = components.iter().map(|(candidate, _)| candidate).collect();
                panic!("{name} is not a component: {names:?}")
            },
            |(_, schema)| serde_json::to_value(schema).unwrap(),
        )
    }

    /// The component of `name` in the shared list, as JSON.
    fn shared(name: &str) -> Value {
        component(&shared_components(), name)
    }

    #[test]
    fn enumerations_are_components_with_the_values_of_the_domain() {
        macro_rules! values_match {
            ($($ty:ty),+ $(,)?) => {$(
                let name = <$ty as JsonSchema>::schema_name();
                let schema = shared(&name);
                let expected: Vec<Value> = <$ty>::ALL
                    .iter()
                    .map(|value| serde_json::to_value(value).unwrap())
                    .collect();
                assert_eq!(schema["type"], "string", "{name}");
                assert_eq!(schema["enum"], Value::Array(expected), "{name}");
                assert!(schema.get("oneOf").is_none(), "{name} still lists alternatives: {schema}");
            )+};
        }
        values_match!(
            CalendarKind,
            PrincipalKind,
            PrincipalStatus,
            TenantStatus,
            GrantAccess,
            GrantStatus,
            GrantSource,
            FeedMode,
            TokenKind,
            EventType,
            ExternalAccountStatus,
            PartStat,
            Access,
            Transparency,
            EventStatus,
        );
        assert_eq!(
            shared("CalendarKind")["enum"],
            json!(["personal", "group", "managed", "user", "mirror"])
        );
        assert_eq!(shared("GrantAccess")["enum"], json!(["read", "read_write", "admin"]));
    }

    #[test]
    fn fields_of_shared_types_are_references_to_their_components() {
        for (reference, name) in [
            (calendar_kind(), "CalendarKind"),
            (part_stat(), "PartStat"),
            (tenant_settings(), "TenantSettings"),
            (event_time(), "EventTime"),
            (recurrence(), "Recurrence"),
            (audit_actor(), "AuditActor"),
            (event_data(), "EventData"),
        ] {
            assert_eq!(
                serde_json::to_value(reference).unwrap(),
                json!({"$ref": format!("#/components/schemas/{name}")})
            );
            let _defined = shared(name);
        }
    }

    #[test]
    fn every_type_the_bridge_serves_converts_without_falling_back() {
        fn converts<T: JsonSchema + ?Sized>() {
            let bridged = try_bridge::<T>().unwrap_or_else(|error| panic!("{}: {error}", T::schema_name()));
            assert_ne!(
                serde_json::to_value(&bridged.schema).unwrap(),
                json!({"type": "object"}),
                "{} came out empty",
                T::schema_name()
            );
        }
        converts::<crate::EventView>();
        converts::<EventData>();
        converts::<davhaven_domain::AuditActor>();
        converts::<davhaven_domain::TenantSettings>();
        converts::<davhaven_domain::EventTime>();
        converts::<davhaven_domain::Recurrence>();
        converts::<Scope>();
        assert!(shared_components().len() > 20);
    }

    #[test]
    fn bridged_schemas_keep_properties_and_required_fields() {
        let bridged = serde_json::to_value(bridge::<davhaven_domain::AuditActor>()).unwrap();
        assert_eq!(bridged["type"], "object");
        assert!(bridged["properties"]["kind"].is_object(), "{bridged}");
        assert!(bridged["properties"]["principal_id"].is_object(), "{bridged}");
    }

    #[test]
    fn the_values_of_documented_enumerations_survive_the_bridge() {
        // `schemars` writes an enumeration whose variants have documentation as `oneOf` of constants; read as an
        // OpenAPI schema that lost every value. The event model has several of them.
        let components = bridged_components::<crate::EventView>();
        let alarm = component(&components, "EventAlarm");
        let target = alarm["properties"]["action"]["$ref"].as_str().unwrap_or_default();
        let name = target.rsplit('/').next().unwrap_or_default();
        let schema = component(&components, name);
        assert_eq!(schema["type"], "string", "{name}: {schema}");
        assert_eq!(schema["enum"], json!(["display", "audio", "email"]), "{name}: {schema}");
        let description = schema["description"].as_str().unwrap();
        assert!(description.contains("- `display`: "), "{description}");
    }

    #[test]
    fn a_tagged_union_is_polymorphic_with_a_component_per_alternative() {
        let components = bridged_components::<crate::EventView>();
        let trigger = component(&components, "AlarmTrigger");
        assert_eq!(trigger["discriminator"]["propertyName"], "type", "{trigger}");
        assert_eq!(
            trigger["discriminator"]["mapping"],
            json!({
                "relative": "#/components/schemas/AlarmTriggerRelative",
                "absolute": "#/components/schemas/AlarmTriggerAbsolute"
            })
        );
        assert_eq!(
            trigger["oneOf"],
            json!([
                {"$ref": "#/components/schemas/AlarmTriggerRelative"},
                {"$ref": "#/components/schemas/AlarmTriggerAbsolute"}
            ])
        );
        for (name, tag, field) in [
            ("AlarmTriggerRelative", "relative", "offset"),
            ("AlarmTriggerAbsolute", "absolute", "at"),
        ] {
            let alternative = component(&components, name);
            assert_eq!(alternative["properties"]["type"]["enum"], json!([tag]), "{name}");
            assert!(alternative["properties"][field].is_object(), "{name}: {alternative}");
            assert!(
                alternative["required"].as_array().unwrap().contains(&json!("type")),
                "{name} names its tag"
            );
        }
    }

    #[test]
    fn unions_that_are_not_tagged_objects_stay_as_they_are() {
        let mut hoisted = Vec::new();
        let mut mixed = json!({"oneOf": [
            {"type": "object", "properties": {"type": {"enum": ["a"]}}, "required": ["type"]},
            {"type": "string"}
        ]});
        let before = mixed.clone();
        hoist_tagged_union("Mixed", &mut mixed, &mut hoisted);
        assert_eq!(mixed, before);
        assert_eq!(hoisted, Vec::<(String, Value)>::new());
        assert_eq!(pascal_case("this_and_future"), "ThisAndFuture");
    }

    #[test]
    fn constants_become_one_value_enums_and_string_constants_one_enumeration() {
        let mut schema = json!({
            "description": "Which side.",
            "oneOf": [
                {"type": "string", "const": "left", "description": "The left\nside."},
                {"type": "string", "const": "right"}
            ],
            "properties": {"const": {"const": 7}}
        });
        normalize(&mut schema);
        assert_eq!(schema["type"], "string");
        assert_eq!(schema["enum"], json!(["left", "right"]));
        assert!(schema.get("oneOf").is_none());
        assert_eq!(
            schema["description"],
            "Which side.\n\nValues:\n- `left`: The left side."
        );
        assert_eq!(
            schema["properties"]["const"],
            json!({"type": "integer", "enum": [7]}),
            "a property called const is a schema, its constant is not touched"
        );

        let mut mixed = json!({"oneOf": [{"type": "string", "const": "a"}, {"type": "integer"}]});
        normalize(&mut mixed);
        assert!(
            mixed["oneOf"].is_array(),
            "alternatives that are not all string constants stay: {mixed}"
        );
        let mut named = json!({"properties": {"const": {"type": "string"}}});
        normalize(&mut named);
        assert_eq!(named, json!({"properties": {"const": {"type": "string"}}}));
    }

    #[test]
    fn a_constant_without_a_type_gets_the_type_of_its_value() {
        for (constant, expected) in [
            (json!("on"), json!({"type": "string", "enum": ["on"]})),
            (json!(true), json!({"type": "boolean", "enum": [true]})),
            (json!(3), json!({"type": "integer", "enum": [3]})),
            (json!(1.5), json!({"type": "number", "enum": [1.5]})),
            (Value::Null, json!({"type": "null", "enum": [null]})),
            // JSON Schema has no single type name for a structured constant; the enum alone says it.
            (json!([1]), json!({"enum": [[1]]})),
        ] {
            let mut schema = json!({"const": constant});
            normalize(&mut schema);
            assert_eq!(schema, expected);
        }
        let mut typed = json!({"type": "integer", "const": 3, "description": "Three."});
        normalize(&mut typed);
        assert_eq!(
            typed,
            json!({"type": "integer", "enum": [3], "description": "Three."}),
            "a type that is there stays"
        );
    }

    #[test]
    fn only_unions_of_at_least_two_bare_string_constants_become_an_enumeration() {
        for (why, alternatives) in [
            ("a single constant", json!([{"type": "string", "const": "only"}])),
            (
                "an alternative with a title",
                json!([{"type": "string", "const": "a"}, {"type": "string", "const": "b", "title": "B"}]),
            ),
            (
                "an alternative of two values",
                json!([{"type": "string", "enum": ["a", "b"]}, {"type": "string", "const": "c"}]),
            ),
        ] {
            let mut schema = json!({"oneOf": alternatives});
            normalize(&mut schema);
            assert!(schema["oneOf"].is_array(), "{why}: {schema}");
            assert!(schema.get("enum").is_none(), "{why}: {schema}");
        }
        // anyOf is read the same way as oneOf; no documented value means no list of values in the description.
        let mut any = json!({"anyOf": [{"type": "string", "const": "x"}, {"type": "string", "const": "y"}]});
        normalize(&mut any);
        assert_eq!(any, json!({"type": "string", "enum": ["x", "y"]}));
    }

    #[test]
    fn only_a_plain_primitive_and_null_merge_into_a_type_list() {
        let mut null_first = json!({"anyOf": [{"type": "null"}, {"type": "integer", "minimum": 0}]});
        normalize(&mut null_first);
        assert_eq!(null_first, json!({"type": ["integer", "null"], "minimum": 0}));
        for (why, mut schema) in [
            (
                "two primitives",
                json!({"anyOf": [{"type": "integer"}, {"type": "string"}]}),
            ),
            (
                "an object and null",
                json!({"anyOf": [{"type": "object", "properties": {}}, {"type": "null"}]}),
            ),
            (
                "three alternatives",
                json!({"anyOf": [{"type": "integer"}, {"type": "null"}, {"type": "string"}]}),
            ),
        ] {
            let before = schema.clone();
            normalize(&mut schema);
            assert_eq!(schema, before, "{why}");
        }
    }

    #[test]
    fn a_union_with_one_tagged_alternative_or_an_untagged_object_is_not_hoisted() {
        let tagged =
            |tag: &str| json!({"type": "object", "properties": {"type": {"enum": [tag]}}, "required": ["type"]});
        let untagged = json!({"type": "object", "properties": {"type": {"enum": ["b"]}}, "required": []});
        let two_values = json!({"type": "object", "properties": {"type": {"enum": ["c", "d"]}}, "required": ["type"]});
        for (why, mut union) in [
            ("one alternative", json!({"oneOf": [tagged("a")]})),
            ("the tag is not required", json!({"oneOf": [tagged("a"), untagged]})),
            ("the tag has two values", json!({"oneOf": [tagged("a"), two_values]})),
            ("no oneOf at all", json!({"anyOf": [tagged("a"), tagged("b")]})),
        ] {
            let before = union.clone();
            let mut hoisted = Vec::new();
            hoist_tagged_union("Union", &mut union, &mut hoisted);
            assert_eq!(union, before, "{why}");
            assert!(hoisted.is_empty(), "{why}");
        }
        assert_eq!(pascal_case("x-ms_kind 2"), "XMsKind2");
        assert_eq!(pascal_case(""), "");
    }

    #[test]
    fn named_primitives_are_plain_properties_and_nullable_primitives_a_type_list() {
        let object = |value: Value| value.as_object().cloned().unwrap();
        let aliases = BTreeMap::from([
            (
                "Locale".to_owned(),
                object(json!({"type": "string", "description": "A BCP 47 tag."})),
            ),
            ("ETag".to_owned(), object(json!({"type": "string", "format": "etag"}))),
        ]);
        let mut value = json!({"properties": {
            "locale": {"$ref": "#/components/schemas/Locale", "default": "en", "description": "The locale."},
            "bare": {"$ref": "#/components/schemas/Locale"},
            "etag": {"anyOf": [{"$ref": "#/components/schemas/ETag"}, {"type": "null"}], "description": "The tag."},
            "other": {"anyOf": [{"$ref": "#/components/schemas/Other"}, {"type": "null"}]}
        }});
        inline_aliases(&mut value, &aliases);
        normalize(&mut value);
        let properties = &value["properties"];
        assert_eq!(
            properties["locale"],
            json!({"type": "string", "default": "en", "description": "The locale."}),
            "a default is a property of a string, not of a reference"
        );
        assert_eq!(
            properties["bare"],
            json!({"type": "string", "description": "A BCP 47 tag."}),
            "the type documents a property that says nothing itself"
        );
        assert_eq!(
            properties["etag"],
            json!({"type": ["string", "null"], "format": "etag", "description": "The tag."})
        );
        assert_eq!(
            properties["other"]["anyOf"][0]["$ref"], "#/components/schemas/Other",
            "references to objects and enumerations stay"
        );
    }

    #[test]
    fn the_bridge_leaves_no_component_for_a_named_primitive() {
        let settings = serde_json::to_value(bridge::<davhaven_domain::TenantSettings>()).unwrap();
        for field in ["locale", "timezone"] {
            let property = &settings["properties"][field];
            assert_eq!(property["type"], "string", "{field}: {property}");
            assert!(property.get("$ref").is_none(), "{field}: {property}");
            assert!(property["default"].is_string(), "{field}: {property}");
        }
        let components = shared_components();
        let primitives: Vec<&String> = components
            .iter()
            .filter(|(_, schema)| {
                let json = serde_json::to_value(schema).unwrap();
                json["type"].is_string() && json.get("enum").is_none() && json.get("properties").is_none()
            })
            .map(|(name, _)| name)
            .collect();
        assert!(
            primitives.is_empty(),
            "named primitives stay components: {primitives:?}"
        );
    }

    #[test]
    fn the_events_document_covers_every_event_type() {
        let document = events_schema();
        let events = document["events"].as_array().unwrap();
        assert_eq!(events.len(), EventType::ALL.len());
        for (entry, event_type) in events.iter().zip(EventType::ALL) {
            assert_eq!(entry["type"], event_type.as_str());
            assert!(entry["payload"].is_object(), "{event_type}");
        }
        assert_eq!(document["envelope_version"], ENVELOPE_VERSION);
        assert!(document["envelope"].is_object());
    }
}
