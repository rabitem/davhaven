//! Reading the JSON Schemas of configuration structures.
//!
//! Every configuration table is a `schemars` schema: the typed tables of [`Config`](crate::config::Config) and the table
//! each registered plugin publishes. Three things read them:
//!
//! * the generated reference ([`crate::docs`]) lists the keys, their types and their defaults;
//! * `davhaven config check` prints the **effective** configuration: [`defaults_tree`] collects the defaults of the schema
//!   and [`merge`] lays the settings of the file and the environment over them;
//! * the check of a plugin that has no validator of its own ([`unknown_keys`]) refuses the keys that the plugin's schema
//!   does not know, so a typo in the table of an adapter this crate has never heard of still fails with the key's name.
//!
//! Schemas that `schemars` derives from `Deserialize` structs with `deny_unknown_fields` have `additionalProperties: false`,
//! `properties` (directly, through a `$ref` into `$defs`, or through `allOf` for flattened structs) and a `default` on every
//! property whose type can be serialized.

use serde_json::{Map, Value};

/// Follows a `$ref` into the `$defs` of the root schema.
pub(crate) fn resolve<'a>(schema: &'a Value, defs: &'a Value) -> &'a Value {
    let Some(reference) = schema.get("$ref").and_then(Value::as_str) else {
        return schema;
    };
    let name = reference.rsplit('/').next().unwrap_or_default();
    defs.get(name).map_or(schema, |target| resolve(target, defs))
}

/// The properties of an object schema, including those of `allOf` members (flattened structs).
pub(crate) fn properties<'a>(schema: &'a Value, defs: &'a Value) -> Vec<(&'a String, &'a Value)> {
    let schema = resolve(schema, defs);
    let mut found: Vec<(&String, &Value)> = Vec::new();
    if let Some(members) = schema.get("properties").and_then(Value::as_object) {
        found.extend(members.iter());
    }
    if let Some(parts) = schema.get("allOf").and_then(Value::as_array) {
        for part in parts {
            found.extend(properties(part, defs));
        }
    }
    found
}

/// Whether a schema is a table with named keys.
pub(crate) fn is_table(schema: &Value, defs: &Value) -> bool {
    !properties(schema, defs).is_empty()
}

/// Whether a schema describes an object with named keys (as opposed to a map or a free-form value).
fn is_object_table(schema: &Value, defs: &Value) -> bool {
    let resolved = resolve(schema, defs);
    is_table(resolved, defs) && resolved.get("type").and_then(Value::as_str) == Some("object")
}

/// The defaults of a schema as a nested document: one member per key that has a default (keys without one, and defaults
/// that are `null`, are left out), tables as nested objects.
pub fn defaults_tree(root: &Value) -> Value {
    let defs = root.get("$defs").unwrap_or(&Value::Null);
    Value::Object(tree_of(root, defs))
}

fn tree_of(schema: &Value, defs: &Value) -> Map<String, Value> {
    let mut tree = Map::new();
    for (key, sub) in properties(schema, defs) {
        if is_object_table(sub, defs) {
            let nested = tree_of(sub, defs);
            if !nested.is_empty() {
                tree.insert(key.clone(), Value::Object(nested));
            }
            continue;
        }
        let default = sub.get("default").or_else(|| resolve(sub, defs).get("default"));
        if let Some(default) = default.filter(|default| !default.is_null()) {
            tree.insert(key.clone(), default.clone());
        }
    }
    tree
}

/// Lays `over` on `base`: objects are merged member by member, everything else (including lists) is replaced.
pub fn merge(base: &mut Value, over: &Value) {
    match (base, over) {
        (Value::Object(base), Value::Object(over)) => {
            for (key, value) in over {
                match base.get_mut(key) {
                    Some(existing) => merge(existing, value),
                    None => {
                        base.insert(key.clone(), value.clone());
                    }
                }
            }
        }
        (base, over) => over.clone_into(base),
    }
}

/// The keys of `table` that the schema does not know, and the keys it knows. `None` when the schema does not forbid
/// unknown keys or has no keys to compare with (a free-form table), or when `table` is not a table.
pub fn unknown_keys(schema: &Value, table: &Value) -> Option<(Vec<String>, Vec<String>)> {
    let defs = schema.get("$defs").unwrap_or(&Value::Null);
    let resolved = resolve(schema, defs);
    if resolved.get("additionalProperties") != Some(&Value::Bool(false)) {
        return None;
    }
    let members = table.as_object()?;
    let known: Vec<String> = properties(resolved, defs)
        .into_iter()
        .map(|(key, _)| key.clone())
        .collect();
    let unknown: Vec<String> = members.keys().filter(|key| !known.contains(key)).cloned().collect();
    Some((unknown, known))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn schema() -> Value {
        json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "mode": {"type": "string", "default": "production"},
                "http": {"$ref": "#/$defs/Http"},
                "origin": {"type": ["string", "null"], "default": null},
                "plugin": {"type": "object", "additionalProperties": true, "default": {}}
            },
            "$defs": {
                "Http": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "timeout": {"type": "string", "default": "10s"},
                        "limit": {"type": "integer"}
                    }
                }
            }
        })
    }

    #[test]
    fn defaults_are_collected_into_a_nested_document() {
        let tree = defaults_tree(&schema());
        assert_eq!(
            tree,
            json!({"mode": "production", "http": {"timeout": "10s"}, "plugin": {}}),
            "keys without a default and null defaults are left out"
        );
    }

    #[test]
    fn settings_are_laid_over_defaults_member_by_member() {
        let mut effective = defaults_tree(&schema());
        merge(
            &mut effective,
            &json!({"http": {"limit": 5}, "mode": "dev", "plugin": {"smtp": {"host": "x"}}}),
        );
        assert_eq!(
            effective,
            json!({"mode": "dev", "http": {"timeout": "10s", "limit": 5}, "plugin": {"smtp": {"host": "x"}}})
        );
        let mut list = json!({"routes": ["a", "b"]});
        merge(&mut list, &json!({"routes": ["c"]}));
        assert_eq!(list, json!({"routes": ["c"]}), "lists are replaced, not merged");
    }

    #[test]
    fn unknown_keys_are_found_when_the_schema_forbids_them() {
        let (unknown, known) = unknown_keys(&schema(), &json!({"mode": "dev", "mod": 1})).unwrap();
        assert_eq!(unknown, vec!["mod".to_owned()]);
        assert!(known.contains(&"http".to_owned()));
        assert_eq!(
            unknown_keys(&schema(), &json!({"mode": "dev"})).unwrap().0,
            Vec::<String>::new()
        );
        let open = json!({"type": "object", "properties": {"a": {}}});
        assert!(
            unknown_keys(&open, &json!({"b": 1})).is_none(),
            "a schema that allows other keys has no verdict"
        );
        assert!(unknown_keys(&schema(), &json!("not a table")).is_none());
    }

    #[test]
    fn a_schema_without_keys_takes_no_keys() {
        let empty = json!({"type": "object", "additionalProperties": false});
        let (unknown, known) = unknown_keys(&empty, &json!({"strict": true})).unwrap();
        assert_eq!(unknown, vec!["strict".to_owned()]);
        assert_eq!(known, Vec::<String>::new());
    }
}
