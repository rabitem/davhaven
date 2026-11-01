//! A small JSON Schema validator for the conformance tests.
//!
//! A client of MCP validates the `structuredContent` of a tool result against the `outputSchema` the server
//! announced, and a model validates its arguments against the `inputSchema`. The conformance tests do the same, with
//! the subset of JSON Schema 2020-12 that the generated schemas use: `type` (also as a list), `properties`,
//! `required`, `additionalProperties`, `items`, `$ref` into `$defs`, `allOf`, `anyOf`, `oneOf`, `enum` and `const`.
//! `format`, `description` and the other annotations are not assertions here. A keyword the validator does not know
//! fails the validation loudly instead of passing silently, so a schema that grows cannot weaken the test.

use serde_json::Value;

/// The keywords that only annotate and never reject.
const ANNOTATIONS: &[&str] = &[
    "$schema",
    "$defs",
    "title",
    "description",
    "default",
    "examples",
    "format",
    "minimum",
    "maximum",
    "minLength",
    "maxLength",
    "minItems",
    "maxItems",
    "x-required-scope",
];

/// The keywords the validator evaluates.
const ASSERTIONS: &[&str] = &[
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "$ref",
    "allOf",
    "anyOf",
    "oneOf",
    "enum",
    "const",
];

/// Why `value` does not satisfy the schema `root`, or nothing when it does.
pub(crate) fn violations(root: &Value, value: &Value) -> Vec<String> {
    let mut found = Vec::new();
    check(root, root, value, "", &mut found);
    found
}

fn resolve<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    let pointer = reference.strip_prefix('#')?;
    root.pointer(pointer)
}

fn type_matches(kind: &str, value: &Value) -> bool {
    match kind {
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        "integer" => value.is_i64() || value.is_u64(),
        "number" => value.is_number(),
        _ => false,
    }
}

fn passes(root: &Value, schema: &Value, value: &Value) -> bool {
    let mut found = Vec::new();
    check(root, schema, value, "", &mut found);
    found.is_empty()
}

fn check(root: &Value, schema: &Value, value: &Value, path: &str, found: &mut Vec<String>) {
    let Some(keywords) = schema.as_object() else {
        // `true` accepts everything, `false` nothing.
        if schema == &Value::Bool(false) {
            found.push(format!("{path}: no value is allowed here"));
        }
        return;
    };
    for keyword in keywords.keys() {
        if !ASSERTIONS.contains(&keyword.as_str()) && !ANNOTATIONS.contains(&keyword.as_str()) {
            found.push(format!("{path}: the validator does not know the keyword `{keyword}`"));
        }
    }
    if let Some(reference) = keywords.get("$ref").and_then(Value::as_str) {
        match resolve(root, reference) {
            Some(target) => check(root, target, value, path, found),
            None => found.push(format!("{path}: unresolvable reference {reference}")),
        }
    }
    if let Some(expected) = keywords.get("const")
        && expected != value
    {
        found.push(format!("{path}: expected the constant {expected}, got {value}"));
    }
    if let Some(Value::Array(options)) = keywords.get("enum")
        && !options.contains(value)
    {
        found.push(format!("{path}: {value} is not one of {options:?}"));
    }
    if let Some(kind) = keywords.get("type") {
        let kinds: Vec<&str> = match kind {
            Value::String(kind) => vec![kind.as_str()],
            Value::Array(kinds) => kinds.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        if !kinds.iter().any(|kind| type_matches(kind, value)) {
            found.push(format!("{path}: expected {kinds:?}, got {value}"));
            return;
        }
    }
    if let Some(Value::Array(all)) = keywords.get("allOf") {
        for part in all {
            check(root, part, value, path, found);
        }
    }
    if let Some(Value::Array(any)) = keywords.get("anyOf")
        && !any.iter().any(|part| passes(root, part, value))
    {
        found.push(format!("{path}: none of the alternatives of anyOf matches {value}"));
    }
    if let Some(Value::Array(one)) = keywords.get("oneOf") {
        let matching = one.iter().filter(|part| passes(root, part, value)).count();
        if matching != 1 {
            found.push(format!(
                "{path}: {matching} alternatives of oneOf match {value}, expected exactly one"
            ));
        }
    }
    if let Value::Object(members) = value {
        check_object(root, keywords, members, path, found);
    }
    if let (Value::Array(items), Some(item_schema)) = (value, keywords.get("items")) {
        for (index, item) in items.iter().enumerate() {
            check(root, item_schema, item, &format!("{path}/{index}"), found);
        }
    }
}

fn check_object(
    root: &Value,
    keywords: &serde_json::Map<String, Value>,
    members: &serde_json::Map<String, Value>,
    path: &str,
    found: &mut Vec<String>,
) {
    let properties = keywords.get("properties").and_then(Value::as_object);
    if let Some(Value::Array(required)) = keywords.get("required") {
        for name in required.iter().filter_map(Value::as_str) {
            if !members.contains_key(name) {
                found.push(format!("{path}: the required member `{name}` is missing"));
            }
        }
    }
    for (name, member) in members {
        let declared = properties.and_then(|properties| properties.get(name));
        match (declared, keywords.get("additionalProperties")) {
            (None, Some(Value::Bool(false))) => found.push(format!("{path}: the member `{name}` is not allowed")),
            (Some(schema), _) | (None, Some(schema @ Value::Object(_))) => {
                check(root, schema, member, &format!("{path}/{name}"), found);
            }
            (None, _) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn types_required_members_and_references_are_checked() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "kind": {"$ref": "#/$defs/Kind"},
                "tags": {"type": "array", "items": {"type": "integer"}},
                "maybe": {"type": ["string", "null"]},
            },
            "required": ["name", "kind"],
            "additionalProperties": false,
            "$defs": {"Kind": {"oneOf": [{"const": "a", "type": "string"}, {"const": "b", "type": "string"}]}},
        });
        assert_eq!(
            violations(
                &schema,
                &json!({"name": "x", "kind": "a", "tags": [1, 2], "maybe": null})
            ),
            Vec::<String>::new()
        );
        let bad = violations(&schema, &json!({"kind": "c", "tags": [1, "x"], "extra": 1}));
        assert_eq!(bad.len(), 4, "{bad:?}");
        assert!(bad.iter().any(|line| line.contains("required member `name`")));
        assert!(bad.iter().any(|line| line.contains("`extra` is not allowed")));
        assert!(bad.iter().any(|line| line.contains("/tags/1")));
        assert!(bad.iter().any(|line| line.contains("/kind")));
    }

    #[test]
    fn unknown_keywords_fail_loudly() {
        let bad = violations(&json!({"type": "string", "pattern": "^a"}), &json!("b"));
        assert!(bad.iter().any(|line| line.contains("`pattern`")), "{bad:?}");
    }

    #[test]
    fn any_of_accepts_one_alternative_and_integers_are_not_fractions() {
        let schema = json!({"anyOf": [{"type": "integer"}, {"type": "null"}]});
        assert_eq!(violations(&schema, &json!(3)), Vec::<String>::new());
        assert_eq!(violations(&schema, &json!(null)), Vec::<String>::new());
        assert_eq!(violations(&schema, &json!(3.5)).len(), 1);
        assert_eq!(violations(&schema, &json!("3")).len(), 1);
    }
}
